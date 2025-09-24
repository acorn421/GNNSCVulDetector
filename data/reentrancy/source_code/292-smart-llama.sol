contract SIMPLE_PIGGY_BANK {

    // Mapping to store balances of addresses
    mapping (address => uint) public balances;
    
    // Minimum amount required for withdrawal
    uint public minimumAmount = 1 ether;

    // Contract owner address
    address public owner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Function to collect funds
    function Collect(uint _amount) public payable onlyOwner {
        require(balances[msg.sender] >= minimumAmount, "Insufficient balance");
        require(_amount <= balances[msg.sender], "Amount exceeds balance");
        
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= _amount;
    }
}