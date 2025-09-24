contract LuckyETH {

    mapping(address => uint) private pendingWithdrawals;

    address private contractOwner;

    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    function playerWithdrawPendingTransactions() public onlyOwner returns (bool) {
        uint amountToWithdraw = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;

        if (msg.sender.call.value(amountToWithdraw)()) {
            return true;
        } else {
            pendingWithdrawals[msg.sender] = amountToWithdraw;
            return false;
        }
    }
}