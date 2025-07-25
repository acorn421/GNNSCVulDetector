/*
 * ===== SmartInject Injection Details =====
 * Function      : buyTokens
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **State Modification Before External Call**: Moving `tokensPurchased = true` before the external call creates an inconsistent state window.
 * 
 * 2. **Additional External Call**: Adding an extra call to `tokenContract.getCurrentPrice(this)` after the main purchase creates a second reentrancy point.
 * 
 * 3. **Multi-Transaction Exploitation Window**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls buyTokens(), which sets tokensPurchased=true and makes external call
 *    - **During external call**: Malicious token contract can call back into the syndicate
 *    - **Transaction 2**: Since tokensPurchased is now true, other functions like withdrawSyndicateTokens() become accessible
 *    - **Transaction 3**: Attacker can exploit the inconsistent state where tokens are marked as purchased but exchange rate setup is incomplete
 * 
 * 4. **Stateful Dependency**: The vulnerability depends on the persistent state change of `tokensPurchased` being set before the external calls complete, allowing subsequent transactions to operate on inconsistent state.
 * 
 * 5. **Realistic Attack Vector**: A malicious token contract could use the callback to trigger other syndicate functions in separate transactions, exploiting the intermediate state where purchase is marked complete but finalization is pending.
 * 
 * The key insight is that this creates a multi-transaction attack where the first transaction establishes the vulnerable state, and subsequent transactions can exploit this state before the original transaction's effects are fully realized.
 */
pragma solidity ^0.4.10;

library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

//SkrillaToken interface containing functions used by the syndicate contract.
contract SkrillaTokenInterface {
    function transfer(address _to, uint256 _value) public returns (bool);

    function buyTokens() payable public;

    function getCurrentPrice(address _buyer) public constant returns (uint256);

    function tokenSaleBalanceOf(address _owner) public constant returns (uint256 balance);

    function withdraw() public returns (bool);
}

contract TokenSyndicate {
    
    SkrillaTokenInterface private tokenContract;
    /*
    * The address to call to purchase tokens.
    */
    address public tokenContractAddress;
    uint256 public tokenExchangeRate;
 
    /**
    * Timestamp after which a purchaser can get a refund of their investment. As long as the tokens have not been purchased.
    */
    uint256 public refundStart;
    /**
    * The owner can set refundEnabled to allow purchasers to refund their funds before refundStart.
    */
    bool public refundsEnabled;
    bool public tokensPurchased;
    /**
    * Has the withdraw function been called on the token contract.
    * This makes the syndicate's tokens available for distribution.
    */
    bool public syndicateTokensWithdrawn;

    /**
    * The amount of wei collected by the syndicate.
    */
    uint256 public totalPresale;
    address public owner;

    mapping(address => uint256) public presaleBalances;

    event LogInvest(address indexed _to,  uint256 presale);
    event LogRefund(address indexed _to, uint256 presale);
    event LogTokenPurchase(uint256 eth, uint256 tokens);
    event LogWithdrawTokens(address indexed _to, uint256 tokens);
    
    modifier onlyOwner() { 
        assert(msg.sender == owner);  _; 
    }

    modifier onlyWhenTokensNotPurchased() { 
        assert(!tokensPurchased);  _; 
    }
    modifier onlyWhenTokensPurchased() { 
        assert(tokensPurchased); _; 
    }
    modifier onlyWhenSyndicateTokensWithdrawn() {
        assert(syndicateTokensWithdrawn); _; 
    }
    modifier whenRefundIsPermitted() {
        require(now >= refundStart || refundsEnabled);
        _;
    }
    modifier onlyWhenRefundsNotEnabled() {
        require(!refundsEnabled);
        _;
    }
    function TokenSyndicate(address _tokenContractAddress,
                            address _owner,
                            uint256 _refundStart) {
        tokenContractAddress = _tokenContractAddress;
        owner = _owner;

        assert(tokenContractAddress != address(0));   // the token contract may not be at the zero address.
        assert(owner != address(0));   // the token contract may not be at the zero address.

        tokenContract = SkrillaTokenInterface(_tokenContractAddress);
        refundStart = _refundStart;

        totalPresale = 0;
        
        tokensPurchased = false;
        syndicateTokensWithdrawn = false;
        refundsEnabled = false;
    }

    // Fallback function can be used to invest in syndicate
    function() external payable {
        invest();
    }
    /*
        Invest in this contract in order to have tokens purchased on your behalf when the buyTokens() contract
        is called without a `throw`.
    */
    function invest() payable public onlyWhenTokensNotPurchased {
        assert(msg.value > 0);

        presaleBalances[msg.sender] = SafeMath.add(presaleBalances[msg.sender], msg.value);
        totalPresale = SafeMath.add(totalPresale, msg.value);        
        LogInvest(msg.sender, msg.value);       // create an event
    }

    /*
        Get the presaleBalance (ETH) for an address.
    */
    function balanceOf(address _purchaser) external constant returns (uint256 presaleBalance) {
        return presaleBalances[_purchaser];
    }

    /**
    * An 'escape hatch' function to allow purchasers to get a refund of their eth before refundStart.
    */
    function enableRefunds() external onlyWhenTokensNotPurchased onlyOwner {
        refundsEnabled = true;
    }
    /*
       Attempt to purchase the tokens from the token contract.
       This must be done before the sale ends

    */
    function buyTokens() external onlyWhenRefundsNotEnabled onlyWhenTokensNotPurchased onlyOwner {
        require(this.balance >= totalPresale);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Mark purchase as started but not completed
        tokensPurchased = true;
        
        // External call that could potentially reenter
        tokenContract.buyTokens.value(this.balance)();
        
        // Get the exchange rate after the external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        tokenExchangeRate = tokenContract.getCurrentPrice(this);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update state after external call - creates window for multi-transaction exploitation
        if (tokenExchangeRate > 0) {
            // This callback allows the external contract to call back into this contract
            // while tokensPurchased is true but tokenExchangeRate might be stale
            tokenContract.getCurrentPrice(this);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        LogTokenPurchase(totalPresale, tokenContract.tokenSaleBalanceOf(this));
    }

    /*
        Call 'withdraw' on the skrilla contract as this contract. So that the tokens are available for distribution with the 'transfer' function.
        This can only be called 14 days after sale close.
    */
    function withdrawSyndicateTokens() external onlyWhenTokensPurchased onlyOwner {
        assert(tokenContract.withdraw());
        syndicateTokensWithdrawn = true;
    }

    /*
        Transfer an accounts token entitlement to itself.
        This can only be called if the tokens have been purchased by the contract and have been withdrawn by the contract.
    */

    function withdrawTokens() external onlyWhenSyndicateTokensWithdrawn {
        uint256 tokens = SafeMath.div(SafeMath.mul(presaleBalances[msg.sender], tokenExchangeRate), 1 ether);
        assert(tokens > 0);

        totalPresale = SafeMath.sub(totalPresale, presaleBalances[msg.sender]);
        presaleBalances[msg.sender] = 0;

        /*
           Attempt to transfer tokens to msg.sender.
           Note: we are relying on the token contract to return a success bool (true for success). If this
           bool is not implemented as expected it may be possible for an account to withdraw more tokens than
           it is entitled to.
        */
        assert(tokenContract.transfer( msg.sender, tokens));
        LogWithdrawTokens(msg.sender, tokens);
    }

    /*
        Refund an accounts investment.
        This is only possible if tokens have not been purchased.
    */
    function refund() external whenRefundIsPermitted onlyWhenTokensNotPurchased {
        uint256 totalValue = presaleBalances[msg.sender];
        assert(totalValue > 0);

        presaleBalances[msg.sender] = 0;
        totalPresale = SafeMath.sub(totalPresale, totalValue);
        
        msg.sender.transfer(totalValue);
        LogRefund(msg.sender, totalValue);
    }
}