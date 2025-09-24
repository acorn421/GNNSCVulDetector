contract Blockjack {

    address public adminContractAddress;
    uint256 public startingBankroll;
    uint256 public activeBankroll;

    mapping (address => uint) public playerBalances;

    // Function to distribute profits to admin contract
    function shareProfits() {
        // Check if there are any profits to share
        if (activeBankroll <= startingBankroll) throw;
        
        // Calculate the profit amount
        uint256 profitAmount = activeBankroll - startingBankroll;
        
        // Send profits to admin contract
        if (!adminContractAddress.call.value(profitAmount)()) throw;
        
        // Update bankroll and balances
        activeBankroll -= profitAmount;
        playerBalances[adminContractAddress] -= profitAmount;
    }
}