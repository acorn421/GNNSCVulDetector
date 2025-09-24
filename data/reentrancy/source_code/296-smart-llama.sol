contract SimpleEthBank {

    mapping (address => uint) private balances;

    address private bankOwner;
    
    modifier onlyOwner() {
        require(msg.sender == bankOwner, "Only the owner can call this function");
        _;
    }

    function withdraw(uint _amount) public onlyOwner {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call.value(_amount)("");
        require(success, "Transfer failed");
    }
}