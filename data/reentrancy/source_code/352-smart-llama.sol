contract SFTToken {

    address public developerAddress;
    bool public isMinimumCapAchieved;

    address contractOwner;
    
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    function withdrawFunds() onlyOwner {
        if (0 == this.balance) revert();
        if (!developerAddress.call.value(this.balance)()) revert();
    }
}