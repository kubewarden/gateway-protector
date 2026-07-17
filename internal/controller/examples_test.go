package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// examplesDir is the repository's examples/ directory. This test applies
// every manifest under it against the real, installed CRD schemas (via
// envtest) so the shipped examples can never silently drift out of sync
// with the API as it evolves.
const examplesDir = "../../examples"

var _ = Describe("examples/", func() {
	It("applies cleanly against the installed CRD schemas", func() {
		ctx := context.Background()

		files, err := examplesYAMLFiles(examplesDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).NotTo(BeEmpty(), "expected at least one example under %s", examplesDir)

		for _, file := range files {
			By("applying " + file)
			objs, err := decodeYAMLDocuments(file)
			Expect(err).NotTo(HaveOccurred(), "failed to decode %s", file)
			Expect(objs).NotTo(BeEmpty(), "expected at least one document in %s", file)

			for _, obj := range objs {
				if ns := obj.GetNamespace(); ns != "" {
					Expect(ensureNamespace(ctx, ns)).To(Succeed())
				}

				err := k8sClient.Create(ctx, obj)
				Expect(err).NotTo(HaveOccurred(), "failed to create %s %s/%s from %s",
					obj.GetKind(), obj.GetNamespace(), obj.GetName(), file)
			}
		}
	})
})

// examplesYAMLFiles returns every .yaml/.yml file under dir, recursively.
func examplesYAMLFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml":
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// decodeYAMLDocuments parses every YAML document (separated by "---") in
// path into an unstructured.Unstructured object.
func decodeYAMLDocuments(path string) ([]*unstructured.Unstructured, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var objs []*unstructured.Unstructured
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(content), 4096)
	for {
		obj := &unstructured.Unstructured{}
		if err := decoder.Decode(obj); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(obj.Object) == 0 {
			// Empty document (e.g. a trailing "---").
			continue
		}
		objs = append(objs, obj)
	}
	return objs, nil
}

// ensureNamespace creates namespace if it doesn't already exist.
func ensureNamespace(ctx context.Context, name string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := k8sClient.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}
