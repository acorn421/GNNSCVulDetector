contract Reentrance {
    mapping (address => uint) private balances;

    address private contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Only owner can call this function");
        _;
    }

    function withdrawBalance_fixed() external onlyOwner {
        uint amountToWithdraw = balances[msg.sender];
        balances[msg.sender] = 0;
        if (!(msg.sender.call.value(amountToWithdraw)())) {
            revert("Transfer failed");
        }
    }
}