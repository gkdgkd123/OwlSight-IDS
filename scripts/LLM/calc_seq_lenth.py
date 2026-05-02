from transformers import AutoTokenizer
from datasets import load_dataset

# 加载 Qwen 的分词器（会自动从国内镜像下载极小的分词文件）
tokenizer = AutoTokenizer.from_pretrained("qwen/Qwen3.6-27B", trust_remote_code=True)

# 加载你的数据集
dataset = load_dataset("json", data_files="./data/sft_20260502_1710.jsonl", split="train")

def calculate_length(example):
    # 将 message 转为纯文本
    text = tokenizer.apply_chat_template(example["messages"], tokenize=False)
    # 计算 Token 数量
    tokens = tokenizer(text, truncation=False)["input_ids"]
    return {"length": len(tokens)}

# 计算所有数据的长度
lengths = dataset.map(calculate_length)["length"]

print(f"数据总条数: {len(lengths)}")
print(f"平均长度: {sum(lengths)/len(lengths):.0f} Tokens")
print(f"最长的一条: {max(lengths)} Tokens")