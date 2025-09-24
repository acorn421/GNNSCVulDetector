contract DaoAccount {

    uint256 private _tokenBalance;
    address private _owner;
    address private _daoChallenge;
    uint256 private _tokenPrice;

    modifier onlyOwner() {
        require(_daoChallenge == msg.sender, "Caller is not the DAO challenge");
        _;
    }

    function withdraw(uint256 tokens) external onlyOwner {
        _tokenBalance -= tokens * _tokenPrice;
        (bool success, ) = _owner.call{value: _tokenPrice * tokens}("");
        require(success, "Transfer failed");
    }
}