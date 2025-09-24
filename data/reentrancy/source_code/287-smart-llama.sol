contract HODLWallet {

    mapping(address => uint256) public userBalances;
    uint256 public constant MAX_WITHDRAWAL_AMOUNT = 0.002 * 1 ether;

    // Internal function to handle withdrawals
    function doWithdraw(address userAddress, uint256 withdrawAmount) internal {
        require(withdrawAmount <= MAX_WITHDRAWAL_AMOUNT, "Withdrawal amount exceeds limit");
        require(userBalances[userAddress] >= withdrawAmount, "Insufficient balance");
        
        userBalances[userAddress] -= withdrawAmount;
        (bool success, ) = userAddress.call{value: withdrawAmount}("");
        require(success, "Transfer failed");
    }
}