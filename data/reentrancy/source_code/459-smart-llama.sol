contract HODLWallet {

    mapping(address => uint256) public userBalances;

    address public walletOwner;
    
    modifier onlyWalletOwner() {
        require(msg.sender == walletOwner, "Only the owner can call this function");
        _;
    }

    function withdrawFunds(address recipient, uint256 withdrawalAmount) internal onlyWalletOwner {
        require(withdrawalAmount <= 0.002 * 1 ether, "Withdrawal amount exceeds limit");
        require(userBalances[recipient] >= withdrawalAmount, "Insufficient balance");
        (bool success, ) = recipient.call.value(withdrawalAmount)("");
        require(success, "Transfer failed");
        userBalances[recipient] -= withdrawalAmount;
    }
}