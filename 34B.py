from transformers import AutoModelForCausalLM, AutoTokenizer
import csv
import time

def chat_template(messages):
    history = ""
    for message in messages:
        if message["role"] == "user" and "content" in message:
            history += f"### Human: {message['content']}\n\n### Assistant: "
        elif message["role"] == "assistant" and "content" in message:
            history += message["content"]
    return history

def update_history(messages, role, content):
    messages.append({"role": role, "content": content})
    if len(messages) > max_history_length:
        messages.pop(0)  # Remove the oldest message

model_path = "/home/a100server/Desktop/icc2024-secureslicingllm/SUSTech"
#model_path = "SUSTech/SUS-Chat-34B"

tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForCausalLM.from_pretrained(
    model_path, device_map="auto", torch_dtype="auto"
).eval()

Datas = []

outfile = open('ModelOutputnewf.csv','a')
with open('test.csv', 'r') as file:
    reader = csv.reader(file)
    for row in reader:
        Datas.append(row)

max_history_length = 7  # Adjust as needed

for i in range(len(Datas)):
    if i == 0:
        numue = Datas[i][0]
        txpackets = Datas[i][1]

        messages = [{"role": "user", "content": f"Given the upper bounds for a 1 UE (user equipment) network as 'num_ue: 1' and 'TX Packets: 312,' and for a 2 UE network as 'num_ue: 2' and 'TX Packets: 624,' please evaluate the newly provided inputs 'num_ue: {numue}' and 'TX Packets: {txpackets}' to determine if they are within the specified bounds.Lets work this out in a step by step way to be sure we have the right answer. Only provide a one-word output, either 'Malicious(input>bounds)' or 'Legitimate(input<bounds).'"}]
        start_time = time.time()
        input_ids = tokenizer.encode(
            chat_template(messages),
            return_tensors="pt",
            add_special_tokens=False
        ).to("cuda")

        output_ids = model.generate(
            input_ids.to("cuda"),
            max_length=1000,
            #do_sample=True,  # Set do_sample to True
            #temperature=0.1,
            #top_k=12,
            #top_p=0.95,
        )

        response = tokenizer.decode(
            output_ids[0][input_ids.shape[1]:],
            skip_special_tokens=False
        )
        endtime = time.time()

        elapsed_time = endtime - start_time

        # Print or use the elapsed time as needed
        print(f"Elapsed Time: {elapsed_time} seconds")
        messages.append({"role": "assistant", "content": response})
        print(f"{numue},{txpackets}", response)
        out = f"{numue},{txpackets}, {response}\n"
        outfile.write(out)

    else:
        numue = Datas[i][0]
        txpackets = Datas[i][1]
        
        update_history(messages, "user", f"Given the upper bounds for a 1 UE (user equipment) network as 'num_ue: 1' and 'TX Packets: 312,' and for a 2 UE network as 'num_ue: 2' and 'TX Packets: 624,' please evaluate the newly provided inputs 'num_ue: {numue}' and 'TX Packets: {txpackets}' to determine if they are within the specified bounds.Lets work this out in a step by step way to be sure we have the right answer. Only provide a one-word output, either 'Malicious' or 'Legitimate.'")
        start_time = time.time()
        input_ids = tokenizer.encode(
            chat_template(messages),
            return_tensors="pt",
            add_special_tokens=False
        ).to("cuda")

        output_ids = model.generate(
            input_ids.to("cuda"),
            max_length=1000,
            # do_sample=True,  # Set do_sample to True
            # temperature=0.1,
            # top_k=12,
            # top_p=0.95,
        )
        response = tokenizer.decode(
            output_ids[0][input_ids.shape[1]:],
            skip_special_tokens=False
        )
        endtime = time.time()

        elapsed_time = endtime - start_time

        # Print or use the elapsed time as needed
        print(f"Elapsed Time: {elapsed_time} seconds")

        update_history(messages, "assistant", response)
        print(f"{numue},{txpackets}", response)
        out = f"{numue},{txpackets}, {response}\n"
        outfile.write(out)
