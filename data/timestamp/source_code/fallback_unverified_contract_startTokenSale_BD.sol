/*
 * ===== SmartInject Injection Details =====
 * Function      : startTokenSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability. The vulnerability requires multiple transactions to exploit: 1) startTokenSale() to begin the sale, 2) purchaseTokens() to buy tokens at timestamp-dependent prices, and 3) claimTokens() after a timestamp-dependent waiting period. Malicious miners can manipulate block timestamps to get better prices during purchase and reduce waiting times for claiming, but the exploitation requires coordinated timestamp manipulation across multiple blocks and transactions.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;
    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/// ERC20 standard，Define the minimum unit of money to 18 decimal places,
/// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Internal transfer, only can be called by this contract.
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account.
     *
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address.
     *
     * Send `_value` tokens to `_to` in behalf of `_from`.
     *
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     * @param _extraData some extra information to send to the approved contract.
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

     /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly.
     *
     * @param _value the amount of money to burn.
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account.
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender.
     * @param _value the amount of money to burn.
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}





/****************************/
/*       ------------        */
/*       HGH TOKEN        */
/*       ------------        */
/****************************/




/// HGH Protocol Token.
contract HGHToken is owned, TokenERC20 {

    string public constant name = "Human Growth Hormone";
    string public constant symbol = "HGH";
    uint8 public constant decimals = 0;

    // Move state variables here (must not be inside function)
    uint256 public saleStartTime;
    uint256 public saleEndTime;
    uint256 public salePrice;
    bool public saleActive;
    mapping(address => uint256) public purchaseTimestamps;
    mapping(address => uint256) public purchaseAmounts;
    
    uint256 public totalSupply = 1000000;

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function HGHToken() public {
        balanceOf[msg.sender] = totalSupply;
    }

    /**
     * Start a token sale with time-dependent pricing
     * 
     * @param _duration Sale duration in seconds
     * @param _basePrice Base price per token in wei
     */
    function startTokenSale(uint256 _duration, uint256 _basePrice) onlyOwner public {
        require(_duration > 0);
        require(_basePrice > 0);
        
        saleStartTime = now;
        saleEndTime = now + _duration;
        salePrice = _basePrice;
        saleActive = true;
    }
    
    /**
     * Purchase tokens during sale with timestamp-dependent pricing
     * Creates a multi-transaction vulnerability where users can manipulate timing
     */
    function purchaseTokens() public payable {
        require(saleActive);
        require(now >= saleStartTime && now <= saleEndTime);
        require(msg.value > 0);
        
        // Vulnerable: Price calculation depends on block.timestamp
        // Miners can manipulate timestamp to get better prices
        uint256 timeElapsed = now - saleStartTime;
        uint256 saleDuration = saleEndTime - saleStartTime;
        
        // Price increases over time - early buyers get better prices
        uint256 currentPrice = salePrice + (salePrice * timeElapsed) / saleDuration;
        uint256 tokenAmount = msg.value / currentPrice;
        
        require(tokenAmount > 0);
        
        // Store purchase info for later claim
        purchaseTimestamps[msg.sender] = now;
        purchaseAmounts[msg.sender] += tokenAmount;
    }
    
    /**
     * Claim purchased tokens after a waiting period
     * Vulnerable to timestamp manipulation across multiple transactions
     */
    function claimTokens() public {
        require(purchaseAmounts[msg.sender] > 0);
        require(purchaseTimestamps[msg.sender] > 0);
        
        // Vulnerable: Requires 24 hours to pass based on timestamp
        // Malicious miners can manipulate this waiting period
        require(now >= purchaseTimestamps[msg.sender] + 24 hours);
        
        uint256 amount = purchaseAmounts[msg.sender];
        purchaseAmounts[msg.sender] = 0;
        
        // Mint tokens to claimer
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }

    function mint(uint amount) onlyOwner public {
        require(amount != 0x0);
        require(amount < 1e60);
        require(totalSupply + amount > totalSupply);
       
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }
}
