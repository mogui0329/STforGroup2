# 1. Introduction

This project is written to test another project about monitoring Linux kernel indices, a assignment of Software Testing from College of Software, NKU.

Old Tested Project: [https://github.com/Asher459/ST_lab](https://github.com/Asher459/ST_lab)
New Tested Project: [https://github.com/Asher459/st_eunomia](https://github.com/Asher459/st_eunomia)
Original Tested Project: [https://github.com/eunomia-bpf/eunomia-template](https://github.com/eunomia-bpf/eunomia-template)

## 1.1 实验目的

1. 测试系统中的各个功能模块是否满足项目要求，并测试是否存在 bug。预期达到能够使系统进行快速的改进和系统的提高。为了在软件投入真实场景运行之前，尽可能多地发现系统的错误;
2. 确保系统完成了所要求或公布的功能，并且可以访问到的功能都有明确的书面说明， 包括使用说明，接口说明，部署说明;
3. 确保系统满足功能和性能的要求;
4. 确保系统是健壮的和适应环境的。

## 1.2 实验对象

Linux主机eBPF监控。

## 1.3 实验任务

开发组需要提供部署说明，接口说明，使用说明等必要的系统使用说明;测试组需要充分 了解测试对象，仔细阅读、分析系统使用说明和项目实践要求，对待测系统的部署、功能. 性能等进行分析，制订测试计划。

## 1.4 实验内容

1. 组内交流。阅读、讨论系统使用说明，分析、研究待测系统;
2. 制定部署测试策略，确定测试实验环境等工作重点;
3. 制定功能测试策略，确定测试方法、重点待测功能等实验内容;
4. 制定单元测试策略，确定测试方法、重点待测代码等实验内容;
5. 制定性能测试策略，确定测试方法、压力负载测试等实验内容;
7. 讨论测试工作具体分工及进度安排，然后按计划进行测试工作;
8. 完成里程碑测试工作后，根据测试结果和缺陷记录，编写测试报告。

## 1.5 实验要求

实验测试应包括的内容，但不限于:


1. 系统基本情况:系统运行环境、资源;
2. 课程实践说明:所要测试的功能项、侧重点;
3. 测试策略设计:描述如何高效、完善地开展测试;
4. 测试资源配置:各测试阶段的任务、所需的资源;
5. 测试结果记录:各测试阶段的测试案例、缺陷说明等。

# 2. Procedures

Explain the procedures unfolded for software testing as well as details inside each procedure.

## 2.1 部署测试

### 2.1.1 测试目的

为了完成软件测试工作所必需的计算机硬件、软件、网络设备等的总称，确定系统是否成功安装 / 部署。稳定和可控的测试环境，可以使测试人员花费较少的时间就完成测 试用例的执行，无需为测试用例、测试过程的维护花费额外的时间，并且可以保证每一个 被提交的缺陷都可以在任何时候被准确的重现。

### 2.1.2 测试任务

- 由开发组提供尽可能详尽的部署说明，针对测试对象，基于部署说明进行部署测试；
- 测试能否成功部署系统，以完成后续测试。并记录测试过程、结果，完成测试报告的部署测试部分。

### 2.1.3 测试内容与步骤

1. 利用人工审查或评估等方法来验证部署说明是否完整、准确; 
2. 验证部署过程中异常情况的处理是否合理、准确; 
3. 验证部署后，系统是否能够正常运行;
4. 完成测试报告的部署测试部分，主要包括测试过程、测试难点、异常情况等。

### 2.1.4 结果展示

Dependencies:
- docker, container: ghcr.io/eunomia-bpf/eunomia-template:latest
- [direnv](https://github.com/direnv/direnv), [nix](https://github.com/NixOS/nix)

```bash
# Get started.
sudo docker run --rm -it --privileged ghcr.io/eunomia-bpf/eunomia-template:latest
sudo apt update && sudo apt install -y direnv
curl -sfL https://direnv.net/install.sh | bash  # sh <(curl -L https://nixos.org/nix/install) --daemon
direnv allow
# Clone repository.
git clone --depth 1 https://github.com/Asher459/st_eunomia.git
# Install dependencies.
sudo apt update && \
sudo apt install -y --no-install-recommends libelf1 libelf-dev zlib1g-dev make clang llvm
# Build the project.
make build
# Run the project.
ecli run src/package.json

# Or run with Github Packages locally.
docker run --rm -it --privileged -v $(pwd):/examples ghcr.io/eunomia-bpf/eunomia-template:latest
```

## 2.2 功能测试

## 2.3 单元测试

## 2.4 性能测试

# 3. Usage

Explain how to use script codes to accomplish unit and performance tests.