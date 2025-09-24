contract ICOBuyer {

    // Address of the token sale contract
    address public tokenSale;

    // Contract owner address
    address public contractOwner;

    // Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == contractOwner);
        _;
    }

    // Function to purchase tokens from the sale
    function purchaseTokens() onlyOwner {
        require(tokenSale.call.value(this.balance)());
    }
}