import os
from dataclasses import dataclass, field
from typing import Optional
from datasets.arrow_dataset import Dataset
from peft import PeftModel
from peft import LoraConfig, get_peft_model
import socket
import json

import torch
from datasets import load_dataset

from transformers import AutoModelForCausalLM, AutoTokenizer
import csv
import time

model_path = "/home/a100server/Desktop/icc2024-secureslicingllm/SUSTech"

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

max_history_length = 7  # Adjust as needed

tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=False)
model = AutoModelForCausalLM.from_pretrained(
    model_path, device_map="auto", torch_dtype="auto"
).eval()

# Define the server address and port
server_address = ('130.18.64.173', 12345)

# Create a socket and bind it to the server address
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(server_address)
server_socket.listen(1)  # Listen for incoming connections

count = 0
txpackets = 0  # Declare txpackets outside the loop

while True:
    # Accept incoming connection
    print("Waiting for a connection...")
    client_socket, client_address = server_socket.accept()
    print("Accepted connection from:", client_address)

    # Receive JSON data from the client
    data = client_socket.recv(1024)
    print("Client data", data)
    if not data:
        break
    
    try:
        lista = []
        # Deserialize the JSON data
        received_data = json.loads(data.decode('utf-8'))
        if isinstance(received_data, list):
            for metric in received_data:
                lista.append(metric["numericValue"])
        out = ""
        for i in range(len(lista)):
            if i == len(lista) - 1:
                out += f"{lista[i]}"
            else:
                out += f"{lista[i]} "
        print(lista)
        promptinitial = out
        print(out)

        
        # If you want to send the whole KPM report as a prompt, remove 0 from the index
        numue = 1
        txpackets = int(lista[-1])
        print(numue, txpackets)
        
        if count == 0:

            messages = [{"role": "user", "content": f"Given the upper bounds for a 1 UE (user equipment) network as 'num_ue: 1' and 'TX Packets: 304,' and for a 2 UE network as 'num_ue: 2' and 'TX Packets: 624,' please evaluate the newly provided inputs 'num_ue: {numue}' and 'TX Packets: {txpackets}' to determine if they are within the specified bounds. Let's work this out in a step-by-step way to be sure we have the right answer. Only provide a one-word output, either 'Malicious' or 'Legitimate.'"}]

            
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
            client_socket.send(response.encode('utf-8'))
            print("I sent the ", response)
            endtime = time.time()

            elapsed_time = endtime - start_time

            # Print or use the elapsed time as needed
            print(f"Elapsed Time: {elapsed_time} seconds")
        
            messages.append({"role": "assistant", "content": response})
            print(f"{numue},{txpackets}", response)
            count += 1
        else:
            
            update_history(messages, "user", f"Given the upper bounds for a 1 UE (user equipment) network as 'num_ue: 1' and 'TX Packets: 304,' and for a 2 UE network as 'num_ue: 2' and 'TX Packets: 624,' please evaluate the newly provided inputs 'num_ue: {numue}' and 'TX Packets: {txpackets}' to determine if they are within the specified bounds. Let's work this out in a step-by-step way to be sure we have the right answer. Only provide a one-word output, either 'Malicious' or 'Legitimate.'")
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
            client_socket.send(response.encode('utf-8'))
            print("I sent the ", response)
            endtime = time.time()

            elapsed_time = endtime - start_time

            # Print or use the elapsed time as needed
            print(f"Elapsed Time: {elapsed_time} seconds")

            update_history(messages, "assistant", response)
            print(f"{numue},{txpackets}", response)
            count += 1
    
    except json.JSONDecodeError as e:
        print("JSON decoding error:", str(e))
    client_socket.close()

server_socket.close()
