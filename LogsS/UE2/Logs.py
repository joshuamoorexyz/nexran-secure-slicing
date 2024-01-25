import numpy as np
import csv

# Read CSV data from file
with open('logs.csv', 'r') as file:
    csv_data = list(csv.reader(file))

# Convert strings to floats
data = np.array([[float(entry) for entry in row] for row in csv_data])

# Calculate average for each column
averages = np.mean(data, axis=0)

# Print average values
for i, avg in enumerate(averages, start=1):
    print(f"{avg:.2f}", end = ",")


import matplotlib.pyplot as plt

# Given values
values = [23.07, 24.41, 22.77, 22.77, 22.94, 23.83, 23.24, 22.03, 24.11, 23.24, 22.93, 22.01, 21.59, 21.14, 21.27, 22.17, 6.89, 3.89, 3.30, 3.74, 3.60, 4.04, 3.30, 4.34, 3.89, 3.00, 4.04, 3.30, 4.49, 3.30, 3.59]

# Plotting
plt.plot(values, marker='o', linestyle='-', color='b')
plt.title('ThroughPut')
plt.xlabel('Time in Second')
plt.ylabel('MBits/Second')
plt.grid(True)
plt.show()
