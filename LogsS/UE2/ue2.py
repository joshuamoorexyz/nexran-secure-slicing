import os

# Directory path
directory_path = '/home/prab/Desktop/LogsS/UE2'

# Dictionary to store bitrates for each position across all files
bitrates_by_position = {}

# Loop through files in the UE1 folder
for file_name in os.listdir(directory_path):
    file_path = os.path.join(directory_path, file_name)
    
    # Check if the item is a file, matches the naming pattern, and skip files 4, 7, and 9
    if os.path.isfile(file_path) and file_name.endswith('ue2.txt') and int(file_name[0]) not in [4, 7, 9]:
        with open(file_path, 'r') as file:
            lines = file.readlines()[11:-10]
            print(lines)
            # Extract throughput values
            #throughputs = [line.split()[6] for line in lines]
            #print(throughputs)
            # Convert the values to float
"""     
            bitrate_values = [float(value) for value in throughputs]

            # Calculate differences
            differences = [abs(bitrate_values[i] - bitrate_values[i - 1]) for i in range(1, len(bitrate_values))]

            # Find the position where the difference is the maximum
            max_change_position = max(range(len(differences)), key=lambda i: differences[i])

            # Extract 15 values before and after the max change position
            before = max(0, max_change_position - 15)
            after = min(len(bitrate_values), max_change_position + 15)
            filtered_bitrate = bitrate_values[before:after + 1]

            # Append to the dictionary based on the file name
            if file_name not in bitrates_by_position:
                bitrates_by_position[file_name] = []

            bitrates_by_position[file_name].append(filtered_bitrate)

# Dictionary to store average values for each position across all files
average_values_by_position = {}

# Calculate the average value for each position across all files
for file_name, bitrates_list in bitrates_by_position.items():
    num_positions = len(bitrates_list[0])  # Assuming all files have the same number of positions
    average_values_by_position[file_name] = [sum(values[i]) / len(values) for i in range(num_positions)]

# Print the average values for each file and position
for file_name, avg_values in average_values_by_position.items():
    print(f"File: {file_name}, Average Bitrates: {avg_values}")
"""