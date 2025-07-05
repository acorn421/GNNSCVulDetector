FROM python:3.7-slim

WORKDIR /app

# Install required packages with compatible protobuf version
RUN pip install protobuf==3.20.0 tensorflow==1.14.0 keras==2.2.4 scikit-learn==0.20.2 docopt

# Copy the application code
COPY . .

# Set environment variable for protobuf
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python

# Command to run the application
CMD ["python", "GNNSCModel.py"]