/*
 * ===== SmartInject Injection Details =====
 * Function      : setTokenSaleWindow
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
 * This injection introduces a multi-transaction timestamp dependence vulnerability through a token sale mechanism. The vulnerability requires: 1) Setting up a sale window using setTokenSaleWindow(), 2) Purchasing tokens with purchaseTokens(), and 3) Claiming bonus tokens with claimBonusTokens(). The vulnerability lies in the reliance on block.timestamp for time validations and bonus calculations, which can be manipulated by miners. The stateful nature comes from storing purchase timestamps and amounts that persist between transactions, creating a multi-step exploit path where miners can manipulate timestamps to gain unfair advantages in bonus calculations.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract SwarmBzzTokenERC20 {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;  // 
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for time-based token sale
    uint256 public saleStartTime;
    uint256 public saleEndTime;
    uint256 public salePrice;
    bool public saleActive;
    mapping(address => uint256) public purchaseTimestamp;
    mapping(address => uint256) public purchaseAmount;
    
    // Event for token sale
    event TokenSale(address indexed buyer, uint256 amount, uint256 timestamp);

    function SwarmBzzTokenERC20(uint256 initialSupply, string tokenName, string tokenSymbol) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }
    
    // Function to set token sale window - vulnerable to timestamp manipulation
    function setTokenSaleWindow(uint256 _startTime, uint256 _endTime, uint256 _price) public {
        require(_startTime < _endTime);
        require(_price > 0);
        
        // Vulnerable: Using block.timestamp for time validation
        if (block.timestamp >= _startTime && block.timestamp <= _endTime) {
            saleStartTime = _startTime;
            saleEndTime = _endTime;
            salePrice = _price;
            saleActive = true;
        }
    }
    
    // Function to purchase tokens during sale - multi-transaction vulnerability
    function purchaseTokens() public payable {
        require(saleActive);
        
        // Vulnerable: Relying on block.timestamp for sale window validation
        require(block.timestamp >= saleStartTime && block.timestamp <= saleEndTime);
        require(msg.value > 0);
        
        uint256 tokenAmount = msg.value * salePrice;
        require(tokenAmount <= balanceOf[this]);
        
        // Store purchase info with timestamp - creates stateful vulnerability
        purchaseTimestamp[msg.sender] = block.timestamp;
        purchaseAmount[msg.sender] += tokenAmount;
        
        // Transfer tokens
        balanceOf[this] -= tokenAmount;
        balanceOf[msg.sender] += tokenAmount;
        
        TokenSale(msg.sender, tokenAmount, block.timestamp);
        Transfer(this, msg.sender, tokenAmount);
    }
    
    // Function to claim bonus tokens - requires previous purchase (stateful)
    function claimBonusTokens() public {
        require(purchaseAmount[msg.sender] > 0);
        
        // Vulnerable: Time-based bonus calculation using block.timestamp
        uint256 timeSincePurchase = block.timestamp - purchaseTimestamp[msg.sender];
        require(timeSincePurchase >= 3600); // 1 hour minimum
        
        // Calculate bonus based on time - miners can manipulate this
        uint256 bonusMultiplier = 1;
        if (timeSincePurchase >= 86400) { // 24 hours
            bonusMultiplier = 3;
        } else if (timeSincePurchase >= 43200) { // 12 hours
            bonusMultiplier = 2;
        }
        
        uint256 bonusTokens = (purchaseAmount[msg.sender] * bonusMultiplier) / 100;
        require(bonusTokens <= balanceOf[this]);
        
        balanceOf[this] -= bonusTokens;
        balanceOf[msg.sender] += bonusTokens;
        
        // Reset purchase amount to prevent double claiming
        purchaseAmount[msg.sender] = 0;
        
        Transfer(this, msg.sender, bonusTokens);
    }
    // === END FALLBACK INJECTION ===

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

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

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