import os

# Directory path
directory_path = '/home/prab/Desktop/LogsS/UE1'

# List to store filtered bitrates
all_filtered_bitrates = []

# Loop through files in the UE1 folder
for file_name in os.listdir(directory_path):
    file_path = os.path.join(directory_path, file_name)
    
    # Check if the item is a file and matches the naming pattern
    if os.path.isfile(file_path) and file_name.endswith('ue1.txt'):
        with open(file_path, 'r') as file:
            lines = file.readlines()[11:-10]
            
            # Extract throughput values
            throughputs = [line.split()[6] for line in lines]

            # Convert the values to float
            bitrate_values = [float(value) for value in throughputs]
            #print(bitrate_values)
            #print(bitrate_values)
            # Calculate differences
            differences = [abs(bitrate_values[i] - bitrate_values[i - 1]) for i in range(1, len(bitrate_values))]

            # Find the position where the difference is the maximum
            max_change_position = max(range(len(differences)), key=lambda i: differences[i])
            #print(max_change_position)
            # Extract 15 values before and after the max change position
            before =  max_change_position - 15
            after =  max_change_position + 15
            filtered_bitrate = bitrate_values[before:after + 1]
            #print(filtered_bitrate)
            # Append to the list
            all_filtered_bitrates.append(filtered_bitrate)

# The run test 5, 7 and 9 had values at vastly different posiion, couldn't get reasonable values so I just excluded them.
            
# Print the filtered bitrates for all files in the UE1 folder
for idx, filtered_bitrate in enumerate(all_filtered_bitrates, start=1):
    if idx !=4 and idx!=7 and idx!= 9:
        print(f"File {idx} - Filtered Bitrates: {filtered_bitrate}")
      
        

    #continue