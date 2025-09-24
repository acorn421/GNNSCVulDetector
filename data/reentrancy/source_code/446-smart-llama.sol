contract DividendToken {

    mapping (address => uint) private userCredits;
    uint private totalDividendsCollected = 0;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function collectOwedDividends() public onlyOwner returns (uint) {
        uint dividendAmount = userCredits[msg.sender] / 100;
        require(msg.sender.call.value(dividendAmount)(), "Transfer failed");
        userCredits[msg.sender] -= dividendAmount;
        totalDividendsCollected += dividendAmount;
        return totalDividendsCollected;
    }
}