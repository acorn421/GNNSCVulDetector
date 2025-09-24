contract PrivateBank {

    mapping (address => uint) public userBalances;

    address private bankOwner;
    
    modifier onlyOwner() {
        require(msg.sender == bankOwner, "Only the owner can call this function");
        _;
    }

    function CashOut(uint _amount) external onlyOwner {
        if(_amount <= userBalances[msg.sender]) {
            if(msg.sender.call.value(_amount)()){
                userBalances[msg.sender] -= _amount;
            }
        }
    }
}