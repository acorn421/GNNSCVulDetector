/*
 * ===== SmartInject Injection Details =====
 * Function      : getAirDropTokens
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
 * Introduced a multi-transaction timestamp dependence vulnerability through time-based bonus calculations. The vulnerability allows attackers to:
 * 
 * 1. **Stateful Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker observes current timestamp and plans timing
 *    - Transaction 2+: Attacker or miner manipulates block.timestamp to exploit bonus windows
 *    - Each successful exploitation changes contract state (reduces totalAirDrop, updates balances)
 *    - State changes persist between transactions, enabling accumulated exploitation
 * 
 * 2. **Specific Vulnerability Mechanics**:
 *    - Uses `block.timestamp % 86400 < 3600` for daily bonus (2x multiplier)
 *    - Uses `block.timestamp % 3600 < 300` for hourly bonus (3x multiplier)
 *    - Miners can manipulate timestamps within ~900 second tolerance
 *    - Multiple addresses can exploit the same time windows
 * 
 * 3. **Multi-Transaction Requirements**:
 *    - Requires monitoring contract state across multiple blocks
 *    - Attackers must coordinate timing across multiple transactions
 *    - State changes from successful claims enable further exploitation
 *    - Cannot be exploited atomically in single transaction
 * 
 * 4. **Realistic Attack Scenarios**:
 *    - Miner creates blocks with timestamps in bonus windows
 *    - Attacker uses multiple addresses to claim during manipulated times
 *    - Flash loan attacks combined with timestamp manipulation
 *    - Coordinated attacks across multiple blocks/transactions
 * 
 * This creates a stateful vulnerability where the contract's token distribution can be drained through accumulated timestamp manipulation across multiple transactions.
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

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function KYRIOSToken() public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based bonus calculation - vulnerability injection
        uint256 bonusMultiplier = 1;
        if (block.timestamp % 86400 < 3600) {  // First hour of each day
            bonusMultiplier = 2;
        } else if (block.timestamp % 3600 < 300) {  // First 5 minutes of each hour
            bonusMultiplier = 3;
        }
        
        toGive = toGive.mul(bonusMultiplier);
        
        // Ensure we don't exceed available tokens
        if (toGive > totalAirDrop) {
            toGive = totalAirDrop;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
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
        
        if (_amount > 0 && transferBlacklist[_from] == false) {
            transferBlacklist[_from] = true;
            inspire(_from, toGive);
        }
        if(_amount > 0 && transferBlacklist[_to] == false) {
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