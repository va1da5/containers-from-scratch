package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const CONTAINERS_DIR = "containers"

func main() {
	image, tag := getRequestedImage()

	switch os.Args[1] {
	// go run main.go run <image:tag> <command> <args>
	case "run":
		run(image, tag)
	case "fork":
		fork(image, tag)
	// go run main.go pull <image:tag>
	case "pull":
		pull(image, tag)
	default:
		panic("go run main.go run <image:tag> <command> <args>")
	}
}

type AuthToken struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

type ContainerFSLayer struct {
	BlobSum string `json:"blobSum"`
}

type ContainerImageManifest struct {
	Name         string             `json:"name"`
	Tag          string             `json:"tag"`
	Architecture string             `json:"architecture"`
	FSLayers     []ContainerFSLayer `json:"fsLayers"`
}

func getAuthToken(image string) string {
	var token AuthToken

	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/%s:pull", image)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(fmt.Sprint("Error creating request: ", err))
	}

	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(fmt.Sprint("Error sending request:", err))
	}
	defer resp.Body.Close()

	jsonString, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprint("Error reading response body:", err))
	}

	err = json.Unmarshal(jsonString, &token)
	if err != nil {
		panic(fmt.Sprint("Error:", err))
	}

	return token.Token
}

func downloadBlob(token string, image string, blobSum string) []byte {
	url := fmt.Sprintf("https://registry-1.docker.io/v2/library/%s/blobs/%s", image, blobSum)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(fmt.Sprint("Error creating request:", err))
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		panic(fmt.Sprint("Error sending request:", err))
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprint("Error reading response body:", err))
	}

	return content
}

func extractTarGz(content []byte, path string) {
	must(os.MkdirAll(path, os.ModePerm))

	archiveReader := bytes.NewReader(content)
	gzipReader, err := gzip.NewReader(archiveReader)
	if err != nil {
		log.Fatal(err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			panic(fmt.Sprint("failed to read tar header: ", err))
		}

		target := filepath.Join(path, header.Name)

		switch header.Typeflag {

		case tar.TypeDir:
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				panic(fmt.Sprint("failed to create directory: ", err))
			}

		case tar.TypeReg:
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				panic(fmt.Sprint("failed to create file: ", err))
			}
			defer file.Close()

			if _, err := io.Copy(file, tarReader); err != nil {
				panic(fmt.Sprint("failed to extract file: ", err))
			}

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil {
				panic(fmt.Sprint("failed to create symlink: ", err))
			}

		default:
			log.Printf("Unknown file type: %s in %s", header.Typeflag, header.Name)
		}
	}
}

func saveManifest(content []byte, path string) {
	must(os.WriteFile(filepath.Join(path, "manifest.json"), content, 0644))
}

func getManifest(image string, tag string) (ContainerImageManifest, error) {
	var manifest ContainerImageManifest

	path := filepath.Join(CONTAINERS_DIR, image, tag)

	file, err := os.Open(filepath.Join(path, "manifest.json"))
	if err != nil {
		fmt.Println(err)
		return manifest, err
	}

	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return manifest, err
	}

	err = json.Unmarshal(content, &manifest)
	if err != nil {
		panic(fmt.Sprint("Error:", err))
	}

	return manifest, nil
}

func pull(image string, tag string) {
	var manifest ContainerImageManifest

	token := getAuthToken(image)

	url := fmt.Sprintf("https://registry-1.docker.io/v2/library/%s/manifests/%s", image, tag)

	imagePath := fmt.Sprintf("%s/%s/%s", CONTAINERS_DIR, image, tag)
	must(os.MkdirAll(imagePath, os.ModePerm))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(fmt.Sprint("Error creating request:", err))
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(fmt.Sprint("Error sending request:", err))
	}
	defer resp.Body.Close()

	jsonString, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprint("Error reading response body:", err))
	}

	saveManifest(jsonString, imagePath)

	err = json.Unmarshal(jsonString, &manifest)
	if err != nil {
		panic(fmt.Sprint("Error:", err))
	}

	for _, blob := range manifest.FSLayers {
		blobPath := fmt.Sprintf("%s/%s", imagePath, blob.BlobSum[strings.Index(blob.BlobSum, ":")+1:])
		content := downloadBlob(token, image, blob.BlobSum)
		extractTarGz(content, blobPath)
		fmt.Printf("[+] %s\n", blobPath)
	}
}

func mountFs(image string, tag string) (rootfs string) {

	containerDir := fmt.Sprintf("%s/%s/%s", CONTAINERS_DIR, image, tag)

	manifest, err := getManifest(image, tag)
	if err != nil {
		panic(fmt.Sprint("Error:", err))
	}

	must(os.MkdirAll(filepath.Join(containerDir, "work"), os.ModePerm))
	must(os.MkdirAll(filepath.Join(containerDir, "upper"), os.ModePerm))
	must(os.MkdirAll(filepath.Join(containerDir, "rootfs"), os.ModePerm))

	var lowerFs []string

	for _, blob := range manifest.FSLayers {
		lowerFs = append(lowerFs, filepath.Join(containerDir, blob.BlobSum[strings.Index(blob.BlobSum, ":")+1:]))
	}

	rootfs = filepath.Join(containerDir, "rootfs")

	must(syscall.Mount("overlay2", rootfs, "overlay", 0, fmt.Sprintf("lowerdir=%s,upperdir=%s/upper,workdir=%s/work", strings.Join(lowerFs, ":"), containerDir, containerDir)))

	return
}

func getRequestedImage() (image string, tag string) {
	items := strings.Split(os.Args[2], ":")
	image = items[0]
	tag = "latest"

	if len(items) > 1 {
		tag = items[1]
	}
	return
}

func run(image string, tag string) {

	_, err := getManifest(image, tag)
	if err != nil {
		pull(image, tag)
		run(image, tag)
	}

	start(image, tag)
}

func start(image string, tag string) {
	fmt.Printf("Running %v in %s as user %d in process %d\n", os.Args[3:], os.Args[2], os.Geteuid(), os.Getpid())

	// invokes its own executable with same arguments, but targets child
	cmd := exec.Command("/proc/self/exe", append([]string{"fork"}, os.Args[2:]...)...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Geteuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getegid(),
				Size:        1,
			},
		},
	}
	must(cmd.Run())
}

func setDNSResolver(address string) {
	content := fmt.Sprintf("nameserver %s\n", address)
	must(os.WriteFile("/etc/resolv.conf", []byte(content), 0644))
}

func fork(image string, tag string) {
	fmt.Printf("Running %v in %s as user %d in process %d\n", os.Args[3:], os.Args[2], os.Geteuid(), os.Getpid())
	rootfs := mountFs(image, tag)

	must(syscall.Sethostname([]byte(image)))
	must(syscall.Chroot(rootfs))
	must(os.Chdir("/"))

	setDNSResolver("1.1.1.1")

	must(syscall.Mount("proc", "/proc", "proc", 0, ""))
	must(syscall.Mount("tmp", "/tmp", "tmpfs", 0, ""))

	cmd := exec.Command(os.Args[3], os.Args[4:]...)

	cmd.Env = append(
		[]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		"HOME=/root",
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	must(cmd.Run())

	must(syscall.Unmount("/proc", 0))
	must(syscall.Unmount("/tmp", 0))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
