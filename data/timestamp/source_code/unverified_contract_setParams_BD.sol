/*
 * ===== SmartInject Injection Details =====
 * Function      : setParams
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Injected a timestamp-dependent parameter change system that introduces multiple vulnerabilities:
 * 
 * 1. **State Variables Added** (assumed to be in contract):
 *    - `uint256 lastParamChangeTimestamp` - Tracks when parameters were last changed
 *    - `uint256 paramChangeCooldown = 1 hours` - Cooldown period between changes
 *    - `uint256 emergencyThreshold = 7 days` - Time threshold for emergency mode
 *    - `uint256 emergencyWindow = 2 hours` - Window during which emergency benefits apply
 *    - `bool emergencyMode` - Flag indicating if emergency mode is active
 *    - `uint256 emergencyActivatedAt` - Timestamp when emergency mode was activated
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls setParams() to establish `lastParamChangeTimestamp`
 *    - **Wait Period**: Attacker (if they control mining) or malicious miner manipulates timestamps
 *    - **Transaction 2**: After manipulating block.timestamp, call setParams() again to either:
 *      a) Bypass cooldown period by timestamp manipulation
 *      b) Trigger emergency mode through timestamp manipulation
 *    - **Transaction 3**: Exploit emergency mode window to set parameters beyond normal limits
 * 
 * 3. **Vulnerability Mechanisms**:
 *    - **Timestamp Manipulation**: Miners can manipulate `block.timestamp` within ~15 second tolerance
 *    - **Emergency Mode Exploitation**: By manipulating timestamps, attackers can artificially trigger emergency mode
 *    - **Cooldown Bypass**: Timestamp manipulation can bypass the intended cooldown period
 *    - **Window Exploitation**: Emergency mode creates a time window with relaxed constraints
 * 
 * 4. **Multi-Transaction Requirement**:
 *    - First transaction must establish baseline timestamp
 *    - Subsequent transactions exploit the timestamp-dependent logic
 *    - Multiple calls needed to fully exploit the emergency mode mechanism
 *    - State persistence between transactions enables the vulnerability
 * 
 * The vulnerability is realistic as it implements what appears to be a safety mechanism (emergency mode) but relies on manipulable timestamp values, creating a multi-transaction exploitation path.
 */
pragma solidity ^0.4.23;

library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract SEA {
    using SafeMath for uint256;
    string public name;
    string public symbol;
    uint256 public decimals;
    uint256 public totalSupply;
    address public owner;
    uint256 public basisPointsRate = 0;
    uint256 public maximumFee = 0;
    uint256 public minimumFee = 0;

    // Variables needed for setParams Timestamp Dependence
    uint256 public lastParamChangeTimestamp = 0;
    uint256 public emergencyThreshold = 30 days;
    uint256 public paramChangeCooldown = 1 days;
    bool public emergencyMode = false;
    uint256 public emergencyActivatedAt = 0;
    uint256 public emergencyWindow = 1 days;

    mapping (address => uint256) public balances;
    mapping (address => uint256) public freezes;
    mapping (address => mapping (address => uint256)) public allowed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event CollectFee(address indexed from, address indexed _owner, uint256 fee);
    event Approval(address indexed from, address indexed _spender, uint256 _value);
    event Params(address indexed _owner, uint256 feeBasisPoints, uint256 minFee, uint256 maxFee); 
    event Freeze(address indexed to, uint256 value);
    event Unfreeze(address indexed to, uint256 value);
    event Withdraw(address indexed to, uint256 value);

    constructor(uint256 initialSupply, uint8 decimalUnits, string tokenName, string tokenSymbol) public {
        balances[msg.sender] = initialSupply;
        totalSupply = initialSupply;
        name = tokenName;
        symbol = tokenSymbol;
        decimals = decimalUnits;
        owner = msg.sender;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        uint256 fee = calFee(_value);
        require(_value > fee);
        uint256 sendAmount = _value.sub(fee);
        if (balances[msg.sender] >= _value && _value > 0 && balances[_to] + sendAmount > balances[_to]) {
            balances[msg.sender] = balances[msg.sender].sub(_value);
            balances[_to] = balances[_to].add(sendAmount);
            if (fee > 0) {
                balances[owner] = balances[owner].add(fee);
                emit CollectFee(msg.sender, owner, fee);
            }
            emit Transfer(msg.sender, _to, sendAmount);
            return true;
        } else {
            return false;
        }
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 fee = calFee(_value);
        require(_value > fee);
        uint256 sendAmount = _value.sub(fee);
        if (balances[_from] >= _value && allowed[_from][msg.sender] >= _value && _value > 0 && balances[_to] + sendAmount > balances[_to]) {
            balances[_to] = balances[_to].add(sendAmount);
            balances[_from] = balances[_from].sub(_value);
            allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
            if (fee > 0) {
                balances[owner] = balances[owner].add(fee);
                emit CollectFee(msg.sender, owner, fee);
            }
            emit Transfer(_from, _to, _value);
            return true;
        } else {
            return false;
        }
    }
    
    function freeze(address _to,uint256 _value) public returns (bool success) {
        require(msg.sender == owner);
        require(balances[_to] >= _value);
        require(_value > 0);
        balances[_to] = balances[_to].sub(_value);
        freezes[_to] = freezes[_to].add(_value);
        emit Freeze(_to, _value);
        return true;
    }
    
    function unfreeze(address _to,uint256 _value) public returns (bool success) {
        require(msg.sender == owner);
        require(freezes[_to] >= _value);
        require(_value > 0);
        freezes[_to] = freezes[_to].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Unfreeze(_to, _value);
        return true;
    }
    
    function setParams(uint256 newBasisPoints, uint256 newMinFee, uint256 newMaxFee) public returns (bool success) {
        require(msg.sender == owner);
        require(newBasisPoints <= 20);
        require(newMinFee <= 50);
        require(newMaxFee <= 50);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Timestamp-dependent emergency override mechanism
        if (lastParamChangeTimestamp > 0) {
            // Emergency mode: allow bypassing limits if significant time has passed
            if (block.timestamp - lastParamChangeTimestamp >= emergencyThreshold) {
                emergencyMode = true;
                emergencyActivatedAt = block.timestamp;
            }
            // Regular cooldown period
            else if (block.timestamp - lastParamChangeTimestamp < paramChangeCooldown) {
                revert("Parameter change cooldown period not met");
            }
        }
        
        // Store current block timestamp for future validations
        lastParamChangeTimestamp = block.timestamp;
        
        // Apply emergency mode benefits if activated
        if (emergencyMode && block.timestamp - emergencyActivatedAt < emergencyWindow) {
            // In emergency mode, temporarily allow higher limits
            require(newBasisPoints <= 50); // Increased from 20
            require(newMinFee <= 100);     // Increased from 50  
            require(newMaxFee <= 100);     // Increased from 50
        }
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        basisPointsRate = newBasisPoints;
        minimumFee = newMinFee.mul(10**decimals);
        maximumFee = newMaxFee.mul(10**decimals);
        emit Params(msg.sender, basisPointsRate, minimumFee, maximumFee);
        return true;
    }
    
    function calFee(uint256 _value) private view returns (uint256 fee) {
        fee = (_value.mul(basisPointsRate)).div(10000);
        if (fee > maximumFee) {
            fee = maximumFee;
        }
        if (fee < minimumFee) {
            fee = minimumFee;
        }
    }
    
    function withdrawEther(uint256 amount) public returns (bool success) {
        require (msg.sender == owner);
        owner.transfer(amount);
        emit Withdraw(msg.sender,amount);
        return true;
    }
    
    function destructor() public returns (bool success) {
        require(msg.sender == owner);
        selfdestruct(owner);
        return true;
    }
    
    function() payable private {
    }
}
