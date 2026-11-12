import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

# Load numpy arrays
global_W1 = torch.tensor(np.load("global_W1.npy"), dtype=torch.float32)
global_b1 = torch.tensor(np.load("global_b1.npy"), dtype=torch.float32)
global_W2 = torch.tensor(np.load("global_W2.npy"), dtype=torch.float32)
global_b2 = torch.tensor(np.load("global_b2.npy"), dtype=torch.float32)

update_W1 = torch.tensor(np.load("update_W1.npy"), dtype=torch.float32)
update_W2 = torch.tensor(np.load("update_W2.npy"), dtype=torch.float32)
label = torch.tensor(np.load("label.npy"), dtype=torch.long)

# Define the network architecture matching the weights
class DispatchAuthenticator(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(global_W1.shape[1], global_W1.shape[0])
        self.fc2 = nn.Linear(global_W2.shape[1], global_W2.shape[0])
        
        # Initialize with global weights
        self.fc1.weight.data = global_W1.clone()
        self.fc1.bias.data = global_b1.clone()
        self.fc2.weight.data = global_W2.clone()
        self.fc2.bias.data = global_b2.clone()

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        return self.fc2(x)

model = DispatchAuthenticator()
criterion = nn.CrossEntropyLoss()

# Target gradients from the intercepted update
target_grad_W1 = update_W1  # Depending on learning rate scaling
target_grad_W2 = update_W2

# Optimize a dummy input to match the gradient signature
# (Initialize dummy input randomly or as zero tensor of appropriate shape)
dummy_input = torch.randn((1, global_W1.shape[1]), requires_grad=True)
optimizer = optim.Adam([dummy_input], lr=0.1)

for it in range(1000):
    optimizer.zero_grad()
    output = model(dummy_input)
    loss = criterion(output, label)
    
    # Compute gradients of dummy loss
    grads = torch.autograd.grad(loss, model.parameters(), create_graph=True)
    
    # Match against intercepted updates
    # (Minimize distance between computed gradients and intercepted update gradients)
    loss_reg = torch.sum((grads[0] - target_grad_W1) ** 2) + torch.sum((grads[2] - target_grad_W2) ** 2)
    
    loss_reg.backward()
    optimizer.step()
    
    if it % 100 == 0:
        print(f"Iteration {it}, Loss: {loss_reg.item()}")

print("Reconstructed input/dispatch features:", dummy_input.detach().numpy())
