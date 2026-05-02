import os
import torch
# 训练命令：
# CUDA_VISIBLE_DEVICES=0,1 torchrun --nproc_per_node=2 train.py
# ==========================================
# 1. 基础环境配置
# ==========================================
os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
os.environ["WANDB_DISABLED"] = "true" # 彻底禁用 WandB，防止冲突

from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ⭐ 导入 SwanLab 的 Transformers 专属回调函数
from swanlab.integration.transformers import SwanLabCallback

# ==========================================
# 2. 模型与数据集加载
# ==========================================
model_name = "unsloth/Qwen3.6-27B" # 或你的本地路径
max_seq_length = 8192
print(f"正在加载模型: {model_name} ...")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = model_name, # 或你的本地路径
    max_seq_length = max_seq_length, 
    load_in_4bit = True,
    dtype = None,
)

model = FastLanguageModel.get_peft_model(
    model,
    r = 16,
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                      "gate_proj", "up_proj", "down_proj", "out_proj"],
    lora_alpha = 16,
    lora_dropout = 0,
    bias = "none",
    use_gradient_checkpointing = "unsloth",
    random_state = 3407,
)


print("正在加载并格式化数据集...")
dataset = load_dataset("json", data_files=dataset_path, split="train")

# 1. 先将 Qwen (ChatML) 的标准模板注入给分词器
tokenizer = FastLanguageModel.get_chat_template(
    tokenizer,
    chat_template = "qwen",
    mapping = {"role": "role", "content": "content", "user": "user", "assistant": "assistant"},
)

# 2. 定义一个批处理函数来加速转换
def format_chat(examples):
    # 将 JSON 里的 messages 结构全部转换为 Qwen 认识的 <|im_start|>... 纯文本格式
    texts = [tokenizer.apply_chat_template(msg, tokenize=False, add_generation_prompt=False) for msg in examples["messages"]]
    return {"text": texts}

# 3. 使用 dataset 的 map 方法处理数据
dataset = dataset.map(
    format_chat, 
    batched = True,     # 开启批处理，极速处理数据
    num_proc = 4,       # 调用 4 个 CPU 核心同时干活
)

# ==========================================
# 3. 配置 SwanLab 日志记录器
# ==========================================
# 如果你的服务器能连上国内互联网，会自动同步到 SwanLab 云端。
# 如果是纯物理局域网，请将 mode="cloud" 改为 mode="local"
swanlab_callback = SwanLabCallback(
    project="Qwen-Finetuning",      # 你的项目名称
    experiment_name="27B-4bit-LoRA",# 你的实验名称
    description="双卡4090使用Unsloth微调Qwen3.6-27B",
    workspace=None,                 # 默认传到你的个人空间
    mode="cloud"                    # ⭐ 纯断网环境请改为 "local"
)

# ==========================================
# 4. 配置 SFT 训练器
# ==========================================
output_path = "./qwen_finetune_outputs"
os.makedirs(output_path, exist_ok=True)

trainer = SFTTrainer(
    model = model,
    tokenizer = tokenizer,
    train_dataset = dataset,
    dataset_text_field = "text",
    max_seq_length = max_seq_length,
    dataset_num_proc = 4, # 这是 Hugging Face Datasets 的参数，表示预处理时使用的进程数，可以根据 CPU 核数调整
    args = SFTConfig(
        per_device_train_batch_size = 2, 
        gradient_accumulation_steps = 8, 
        num_train_epochs = 2,
        learning_rate = 2e-4,
        logging_steps = 1,
        optim = "adamw_8bit", 
        weight_decay = 0.001,
        lr_scheduler_type = "linear",
        seed = 3407,
        save_steps = 200,
        save_total_limit = 2,
        save_strategy = "steps",
        report_to = "none", # ⭐ 必须设为 none，因为我们用 callback 手动接管了日志，或者写 "swanlab" 来直接使用 SwanLab 的日志系统
        output_dir = output_path,
        fp16 = not torch.cuda.is_bf16_supported(),
        bf16 = torch.cuda.is_bf16_supported(),
    ),
    callbacks=[swanlab_callback], # ⭐ 将 SwanLab 注入到训练器中
)

trainer = train_on_responses_only(
    trainer,
    instruction_part = "<|im_start|>user\n",
    response_part = "<|im_start|>assistant\n",
)

# ==========================================
# 5. 开始训练
# ==========================================
print("开始训练...")
tokenizer.decode(trainer.train_dataset[100]["input_ids"])
trainer.train()

print("保存最终权重...")
model.save_pretrained("qwen_lora_final")
tokenizer.save_pretrained("qwen_lora_final")
print("微调完成！")