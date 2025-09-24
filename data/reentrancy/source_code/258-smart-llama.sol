contract ELTWagerLedger {

    // Mapping to track token balances for each user and token type
    mapping (address => mapping (address => uint)) public tokenBalances;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to the owner
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    // Function to withdraw tokens
    function withdraw(uint withdrawAmount) {
        // Check if the user has sufficient balance
        if (tokenBalances[address(0)][msg.sender] < withdrawAmount) revert();
        
        // Deduct the amount from the user's balance
        tokenBalances[address(0)][msg.sender] -= withdrawAmount;
        
        // Transfer the amount to the user
        if (!msg.sender.call.value(withdrawAmount)()) revert();
    }
}