// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package RuntimeTest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/logging"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("BenchmarkNetperfPerformance", func() {
	var (
		vm          *helpers.SSHMeta
		monitorStop = func() error { return nil }

		log    = logging.DefaultLogger
		logger = logrus.NewEntry(log)

		PerfLogFile   = "l4bench_perf.log"
		PerfLogWriter bytes.Buffer
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		helpers.ExpectCiliumReady(vm)
	})

	JustBeforeEach(func() {
		monitorStop = vm.MonitorStart()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed(
			"cilium service list",
			"cilium policy get")
	})

	AfterEach(func() {
		LogPerm := os.FileMode(0666)
		testPath, err := helpers.CreateReportDirectory()
		Expect(err).Should(BeNil(), "cannot create log file")
		helpers.WriteOrAppendToFile(filepath.Join(testPath, PerfLogFile), PerfLogWriter.Bytes(), LogPerm)
		PerfLogWriter.Reset()
	}, 500)

	createContainers := func() {
		By("create Client container")
		vm.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		By("create Server containers")
		vm.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
		vm.PolicyDelAll()
		vm.WaitEndpointsReady()
		err := helpers.WithTimeout(func() bool {
			if data, _ := vm.GetEndpointsNames(); len(data) < 2 {
				logger.Info("Waiting for endpoints to be ready")
				return false
			}
			return true
		}, "Endpoints are not ready", &helpers.TimeoutConfig{Timeout: 150})
		Expect(err).Should(BeNil(), "Endpoints timed out.")
	}

	removeContainers := func(containerName string) {
		By("removing container %s", containerName)
		res := vm.ContainerRm(containerName)
		Expect(res.WasSuccessful()).Should(BeTrue(), "Container removal failed")
	}

	deleteContainers := func() {
		removeContainers(helpers.Client)
		removeContainers(helpers.Server)
	}

	superNetperfRRLog := func(client string, server string, num int) {
		res := vm.SuperNetperfRR(client, server, num)
		fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.GetStdOut(), "\n"))
	}

	superNetperfStreamLog := func(client string, server string, num int) {
		res := vm.SuperNetperfStream(client, server, num)
		fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.GetStdOut(), "\n"))
	}

	Context("Benchmark Netperf Tests", func() {
		BeforeAll(func() {
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})

		It("Test L4 Netperf TCP_RR Performance lo:1", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance lo:10", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf Performance lo:100", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance lo:1000", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:1", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:10", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:100", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:1000", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:10", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:100", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1000", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:10", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:100", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1000", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 1000)
		}, 300)
	})

	Context("Benchmark Netperf Tests Sockops-Enabled", func() {
		BeforeAll(func() {
			vm.RestartCiliumSockops()
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})
	})
})
