contract SimpleEthBank {
    // Mapping to store user balances
    mapping (address => uint) private userBalances;
    
    // Mapping to track if an account exists
    mapping (address => bool) private isAccountActive;

    // Contract owner address
    address private contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    // Function to withdraw funds
    function withdraw(uint withdrawalAmount) public onlyOwner {
        require(isAccountActive[msg.sender], "Account does not exist");
        require(userBalances[msg.sender] >= withdrawalAmount, "Insufficient balance");
        
        userBalances[msg.sender] -= withdrawalAmount;
        (bool success, ) = msg.sender.call.value(withdrawalAmount)("");
        require(success, "Transfer failed");
    }
}