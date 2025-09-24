contract TokenPool {

    uint public rewardRate = 30; // Percentage of reward
    uint public totalFunds = 100; // Total amount raised
    address public tokenFactory; // Address of token creation contract
    bytes4 tokenCreationSelector; // Function selector for token creation
    mapping (address => uint) userBalances; // User balances mapping

    function MintTokens() {
        uint mintAmount = totalFunds * (100 - rewardRate) / 100;
        if (!tokenFactory.call.value(mintAmount)(tokenCreationSelector)) throw;
        userBalances[tokenFactory] -= mintAmount;
    }
}