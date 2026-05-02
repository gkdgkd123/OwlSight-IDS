#!/bin/bash
# ==========================================
# 国内环境极速一键配置脚本 (Unsloth + PyTorch)
# ==========================================

echo ">>> [1] 配置 Hugging Face 国内镜像 (永久生效)..."
if grep -q "HF_ENDPOINT" ~/.bashrc; then
    echo "HF_ENDPOINT 已配置"
else
    echo 'export HF_ENDPOINT=https://hf-mirror.com' >> ~/.bashrc
    echo "已将 HF_ENDPOINT 写入 ~/.bashrc"
fi
export HF_ENDPOINT=https://hf-mirror.com

echo ">>> [2] 全局配置 Pip 国内清华源..."
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

echo ">>> [3] 安装核心底座: PyTorch 2.4.0 (CUDA 12.1)..."
# 使用上海交大镜像源极速下载 PyTorch 轮子，避免官方源断流
pip install torch==2.4.0 torchvision torchaudio -f https://mirror.sjtu.edu.cn/pytorch-wheels/torch_stable.html

echo ">>> [4] 安装 Unsloth 底层加速依赖 (xformers, triton, bitsandbytes)..."
# 注意：xformers 必须指定与 PyTorch 匹配的版本
pip install xformers==0.0.32.post2 triton bitsandbytes accelerate peft datasets

echo ">>> [5] 安装微调框架及日志监控 (Unsloth, TRL, SwanLab)..."
pip install unsloth unsloth-zoo trl==0.22.2 transformers==5.2.0 swanlab

echo "=========================================="
echo ">>> 🎉 环境准备完毕！"
echo ">>> 请运行下面这行代码来验证显卡是否就绪："
echo "python -c 'import torch; print(\"CUDA Available:\", torch.cuda.is_available(), \"| GPU:\", torch.cuda.get_device_name(0))'"
echo "=========================================="