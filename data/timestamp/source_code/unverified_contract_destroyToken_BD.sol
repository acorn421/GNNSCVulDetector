/*
 * ===== SmartInject Injection Details =====
 * Function      : destroyToken
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent daily destruction limit mechanism that is vulnerable to timestamp manipulation. The vulnerability requires multiple transactions to exploit as attackers need to: 1) Monitor blockchain timestamps across different blocks, 2) Accumulate state in the dailyDestroyAmount mapping over time, 3) Exploit timestamp boundaries to bypass daily limits through strategic timing of destruction operations. The vulnerability uses block.timestamp division to determine "days" which can be manipulated by miners, and the state persists between transactions making it exploitable across multiple calls.
 */
pragma solidity ^ 0.4.21;

contract owned {
    address public owner;

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
}


/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }

}


contract HomeLoansToken is owned {
    using SafeMath
    for uint256;

    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;
  

    /// @dev Fix for the ERC20 short address attack http://vessenes.com/the-erc20-short-address-attack-explained/
    /// @param size payload size
    modifier onlyPayloadSize(uint size) {
        require(msg.data.length >= size + 4);
        _;
    }

    /* This creates an array with all balances */
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowed;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint value);



    function HomeLoansToken(
        uint256 initialSupply,
        string tokenName,
        uint decimalUnits,
        string tokenSymbol
    ) {
        owner = msg.sender;
        totalSupply = initialSupply.mul(10 ** decimalUnits);
        balanceOf[msg.sender] = totalSupply; // Give the creator half initial tokens
        name = tokenName; // Set the name for display purposes
        symbol = tokenSymbol; // Set the symbol for display purposes
        decimals = decimalUnits; // Amount of decimals for display purposes
    }


    /// @dev Tranfer tokens to address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transfer(address _to, uint256 _value) onlyPayloadSize(2 * 32) returns(bool success) {
        require(_to != address(0));
        require(_value <= balanceOf[msg.sender]);

        // SafeMath.sub will throw if there is not enough balance.
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }


    /// @dev Tranfer tokens from one address to other
    /// @param _from source address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transferFrom(address _from, address _to, uint256 _value) onlyPayloadSize(2 * 32) returns(bool success) {
        require(_to != address(0));
        require(_value <= balanceOf[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    /// @dev Destroy Tokens
    ///@param destroyAmount Count Token
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
mapping(uint256 => uint256) public dailyDestroyAmount;
    uint256 public lastDestroyTime;
    uint256 public constant DAILY_DESTROY_LIMIT = 1000; // 1000 tokens per day
    uint256 public constant DAY_DURATION = 86400; // 24 hours in seconds

    function destroyToken(uint256 destroyAmount) onlyOwner {
        destroyAmount = destroyAmount.mul(10 ** decimals);
        
        // Get current day timestamp (vulnerable to manipulation)
        uint256 currentDay = block.timestamp / DAY_DURATION;
        
        // Check daily destruction limit using manipulable timestamp
        if (dailyDestroyAmount[currentDay].add(destroyAmount) > DAILY_DESTROY_LIMIT.mul(10 ** decimals)) {
            revert("Daily destruction limit exceeded");
        }
        
        // Update daily destruction tracking
        dailyDestroyAmount[currentDay] = dailyDestroyAmount[currentDay].add(destroyAmount);
        lastDestroyTime = block.timestamp;
        
        balanceOf[owner] = balanceOf[owner].sub(destroyAmount);
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        totalSupply = totalSupply.sub(destroyAmount);
    }

    /// @dev Approve transfer
    /// @param _spender holder address
    /// @param _value tokens amount
    /// @return result
    function approve(address _spender, uint _value) returns(bool success) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));

        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /// @dev Token allowance
    /// @param _owner holder address
    /// @param _spender spender address
    /// @return remain amount
    function allowance(address _owner, address _spender) constant returns(uint remaining) {
        return allowed[_owner][_spender];
    }

    /// @dev Withdraw all owner
    function withdraw() onlyOwner {
        msg.sender.transfer(this.balance);
    }
}