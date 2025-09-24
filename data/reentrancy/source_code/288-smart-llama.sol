contract HODLWallet {

    mapping(address => uint256) public userBalances;
    uint256 public constant MAX_WITHDRAWAL_AMOUNT = 0.002 * 1 ether;

    address public walletOwner;

    modifier onlyOwner() {
        require(msg.sender == walletOwner, "Only owner can call this function");
        _;
    }

    function doWithdraw(address recipient, uint256 withdrawalAmount) internal onlyOwner {
        require(withdrawalAmount <= MAX_WITHDRAWAL_AMOUNT, "Withdrawal amount exceeds limit");
        require(userBalances[recipient] >= withdrawalAmount, "Insufficient balance");
        
        userBalances[recipient] = userBalances[recipient] - withdrawalAmount;
        (bool success, ) = recipient.call.value(withdrawalAmount)("");
        require(success, "Transfer failed");
    }
}