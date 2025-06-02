# Use your existing image as the base
FROM cartlabpurdue/mmitss-mrp-x86:AA1.1

# Switch to root user (if needed) to install packages
USER root
ENV DEBIAN_FRONTEND=noninteractive

# Install Python, pip, and development tools (for your Python apps)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    cmake \
    gdb

# Install net-snmp tools, SNMP daemon
RUN apt-get install -y snmp snmpd

# Install PyInstaller (and any other Python packages you might need)
RUN pip3 install --upgrade pip && pip3 install pyinstaller

# Clean up package lists
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /mmitss

# Copy the compiled executable into the image
COPY src/pipeline-1211/bin/M_Solver1211 /mmitss/M_Solver1211
COPY src/mrp/priority-request-server/M_PriorityRequestServer /mmitss/M_PriorityRequestServer