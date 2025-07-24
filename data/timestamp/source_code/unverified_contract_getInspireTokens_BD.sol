/*
 * ===== SmartInject Injection Details =====
 * Function      : getInspireTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a stateful timestamp dependence vulnerability by introducing a time-based bonus system using block.timestamp. The vulnerability stores timestamps in a mapping (lastInspireTime) and provides 20% bonus tokens if more than 1 hour has passed since the last inspire. This creates a multi-transaction vulnerability where:
 * 
 * 1. **First Transaction**: User calls getInspireTokens() to initialize their timestamp and receive base tokens
 * 2. **State Persistence**: The lastInspireTime mapping stores the timestamp across transactions
 * 3. **Waiting Period**: Attacker waits or manipulates time
 * 4. **Second Transaction**: User calls getInspireTokens() again after 1 hour to receive bonus tokens
 * 
 * The vulnerability is exploitable because:
 * - Miners can manipulate block.timestamp within ~900 seconds tolerance
 * - Users can game the system by timing their transactions to maximize bonuses
 * - The time-based logic creates predictable patterns that can be exploited
 * - Multiple calls separated by time intervals are required to fully exploit the bonus system
 * 
 * This requires multiple transactions because the timestamp must be set in one transaction, time must pass (or be manipulated), and then another transaction must occur to claim the bonus. The vulnerability cannot be exploited in a single atomic transaction.
 */
pragma solidity ^0.4.23;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    require(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);
    return c;
  }
}

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; 
}

contract KYRIOSToken {
    using SafeMath for uint256;
    string public name = "KYRIOS Token";
    string public symbol = "KRS";
    uint8 public decimals = 18;
    uint256 public totalSupply = 2000000000 ether;
    uint256 public totalAirDrop = totalSupply * 10 / 100;
    uint256 public eachAirDropAmount = 25000 ether;
    bool public airdropFinished = false;
    mapping (address => bool) public airDropBlacklist;
    mapping (address => bool) public transferBlacklist;
    
    // ADDED: Mapping for lastInspireTime to fix undeclared identifier compilation errors
    mapping (address => uint256) public lastInspireTime;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    constructor() public {
        balanceOf[msg.sender] = totalSupply - totalAirDrop;
    }
    
    modifier canAirDrop() {
        require(!airdropFinished);
        _;
    }
    
    modifier onlyWhitelist() {
        require(airDropBlacklist[msg.sender] == false);
        _;
    }
    
    function airDrop(address _to, uint256 _amount) canAirDrop private returns (bool) {
        totalAirDrop = totalAirDrop.sub(_amount);
        balanceOf[_to] = balanceOf[_to].add(_amount);
        Transfer(address(0), _to, _amount);
        return true;
        
        if (totalAirDrop <= _amount) {
            airdropFinished = true;
        }
    }
    
    function inspire(address _to, uint256 _amount) private returns (bool) {
        if (!airdropFinished) {
            totalAirDrop = totalAirDrop.sub(_amount);
            balanceOf[_to] = balanceOf[_to].add(_amount);
            Transfer(address(0), _to, _amount);
            return true;
            if(totalAirDrop <= _amount){
                airdropFinished = true;
            }
        }
    }
    
    function getAirDropTokens() payable canAirDrop onlyWhitelist public {
        
        require(eachAirDropAmount <= totalAirDrop);
        
        address investor = msg.sender;
        uint256 toGive = eachAirDropAmount;
        
        airDrop(investor, toGive);
        
        if (toGive > 0) {
            airDropBlacklist[investor] = true;
        }

        if (totalAirDrop == 0) {
            airdropFinished = true;
        }
        
        eachAirDropAmount = eachAirDropAmount.sub(0.01 ether);
    }
    
    function getInspireTokens(address _from, address _to,uint256 _amount) payable public{
        uint256 toGive = eachAirDropAmount * 50 / 100;
        if(toGive > totalAirDrop){
            toGive = totalAirDrop;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based bonus system with stored timestamps
        uint256 currentTime = block.timestamp;
        if (lastInspireTime[_from] == 0) {
            lastInspireTime[_from] = currentTime;
        }
        if (lastInspireTime[_to] == 0) {
            lastInspireTime[_to] = currentTime;
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        if (_amount > 0 && transferBlacklist[_from] == false) {
            transferBlacklist[_from] = true;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Apply time-based multiplier for _from
            uint256 timeDiff = currentTime - lastInspireTime[_from];
            if (timeDiff > 3600) { // 1 hour bonus period
                toGive = toGive * 120 / 100; // 20% bonus
            }
            lastInspireTime[_from] = currentTime;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            inspire(_from, toGive);
        }
        if(_amount > 0 && transferBlacklist[_to] == false) {
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            // Apply time-based multiplier for _to
            uint256 timeDiffTo = currentTime - lastInspireTime[_to];
            if (timeDiffTo > 3600) { // 1 hour bonus period
                toGive = toGive * 120 / 100; // 20% bonus
            }
            lastInspireTime[_to] = currentTime;
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            inspire(_to, toGive);
        }
    }
    
    function () external payable {
        getAirDropTokens();
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
        getInspireTokens(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
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
