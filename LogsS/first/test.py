# Read the text file
with open('1ue1.txt', 'r') as file:
    lines = file.readlines()[6:-10]
throughputs = []
for line in lines:
    #print(line)
    a = line.split()
    throughputs.append(a[6])


bitrate_values = throughputs
print(throughputs)


# Convert the values to float
bitrate_values = [float(value) for value in bitrate_values]


differences = [abs(bitrate_values[i] - bitrate_values[i - 1]) for i in range(1, len(bitrate_values))]

# Find the position where the difference is the maximum
max_change_position = max(range(len(differences)), key=lambda i: differences[i])

before = max_change_position -15
after = max_change_position +15

filteredbitrate = bitrate_values[before:after+1]
print(filteredbitrate)

