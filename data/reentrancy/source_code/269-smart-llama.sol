contract DividendToken {

    mapping (address => uint) private userCredits;
    uint private totalDividends;

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function collectOwedDividends() public onlyOwner returns (uint collectedAmount) {
        collectedAmount = userCredits[msg.sender] / 100;
        userCredits[msg.sender] -= collectedAmount;
        require(msg.sender.call.value(collectedAmount)(), "Transfer failed");
        totalDividends += collectedAmount;
        return totalDividends;
    }
}