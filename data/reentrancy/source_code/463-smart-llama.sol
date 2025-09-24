contract Accounting {

    struct Account {
        uint ethBalance;
        address recipient;
    }

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function transact(Account storage account, uint amount, bytes memory data) internal onlyOwner {
        require(account.ethBalance >= amount, "Insufficient balance");
        require(account.recipient.call.value(amount)(data), "Transaction failed");
        account.ethBalance = account.ethBalance - amount;
    }
}