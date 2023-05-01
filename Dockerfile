# Use the official Golang image as a base image
FROM golang:1.20-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the working directory
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code to the working directory
COPY . .

# Build the Go app
RUN go build -o main .

# Expose the port the app will run on
EXPOSE 8080

# Start the app
CMD ["./main"]

