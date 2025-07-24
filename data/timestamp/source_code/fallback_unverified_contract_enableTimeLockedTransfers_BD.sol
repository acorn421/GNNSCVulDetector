/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimeLockedTransfers
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This introduces a timestamp dependence vulnerability through time-locked transfer functionality. The vulnerability is stateful and multi-transaction: 1) Owner must first call enableTimeLockedTransfers() to set duration, 2) Owner calls initiateTimeLock() to lock a user's transfers, 3) Users can call emergencyUnlock() which relies on manipulable timestamps. Miners can manipulate block timestamps to either prevent unlocking or allow premature unlocking, affecting the contract state across multiple transactions.
 */
pragma solidity ^0.4.23;

contract TokenReceiver {
    function tokenFallback(address _from, uint _value, bytes _data) public;
}

contract EgeregToken {
    address public owner;
    string public name = "EgeregToken";
    string public symbol = "MNG";
    uint8 public decimals = 2;
    uint public totalSupply = 0;
    mapping(address => uint) balances;
    mapping (address => mapping (address => uint)) internal allowed;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Time-locked transfer functionality
    mapping(address => uint) transferUnlockTime; // removed 'public' from mapping
    uint public globalTransferLockDuration = 1 hours;

    constructor() public {
        owner = msg.sender;
    }
    
    function enableTimeLockedTransfers(uint _lockDurationHours) external onlyOwner {
        globalTransferLockDuration = _lockDurationHours * 1 hours;
    }

    function initiateTimeLock(address _user) external onlyOwner {
        // Set unlock time based on block timestamp - vulnerable to miner manipulation
        transferUnlockTime[_user] = now + globalTransferLockDuration;
    }

    function checkTransferEligibility(address _user) external view returns (bool) {
        if (transferUnlockTime[_user] == 0) {
            return true; // No time lock set
        }
        // Vulnerable: relies on block.timestamp which miners can manipulate
        return now >= transferUnlockTime[_user];
    }

    function emergencyUnlock(address _user) external {
        // Vulnerable: allows premature unlock if timestamp is manipulated
        require(now >= transferUnlockTime[_user] - 5 minutes, "Emergency unlock not available yet");
        transferUnlockTime[_user] = 0;
    }
    // === END FALLBACK INJECTION ===

    function subtr(uint a, uint b) internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function addit(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        assert(c >= a);
        return c;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function balanceOf(address _owner) external view returns (uint) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) external returns (bool) {
        bytes memory empty;
        transfer(_to, _value, empty);
        return true;
    }

    function transfer(address _to, uint _value, bytes _data) public returns (bool) {
        require(_value <= balances[msg.sender]);
        balances[msg.sender] = subtr(balances[msg.sender], _value);
        balances[_to] = addit(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        if (isContract(_to)) {
            TokenReceiver receiver = TokenReceiver(_to);
            receiver.tokenFallback(msg.sender, _value, _data);
        }
        return true;
    }

    function transferFrom(address _from, address _to, uint _value) external returns (bool) {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balances[_from] = subtr(balances[_from], _value);
        balances[_to] = addit(balances[_to], _value);
        allowed[_from][msg.sender] = subtr(allowed[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint _value) public returns (bool) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function approve(address _spender, uint _value, bytes _data) external returns (bool) {
        approve(_spender, _value);
        require(_spender.call(_data));
        return true;
    }

    function allowance(address _owner, address _spender) external view returns (uint) {
        return allowed[_owner][_spender];
    }

    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = addit(allowed[msg.sender][_spender], _addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function increaseApproval(address _spender, uint _addedValue, bytes _data) external returns (bool) {
        increaseApproval(_spender, _addedValue);
        require(_spender.call(_data));
        return true;
    }

    function decreaseApproval(address _spender, uint _subtractedValue) external returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = subtr(oldValue, _subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function mint(address _to, uint _amount) onlyOwner external returns (bool) {
        totalSupply = addit(totalSupply, _amount);
        balances[_to] = addit(balances[_to], _amount);
        emit Mint(_to, _amount);
        emit Transfer(address(0), _to, _amount);
        return true;
    }

    function burn(uint _value) external {
        require(_value <= balances[msg.sender]);
        address burner = msg.sender;
        balances[burner] = subtr(balances[burner], _value);
        totalSupply = subtr(totalSupply, _value);
        emit Burn(burner, _value);
        emit Transfer(burner, address(0), _value);
    }

    function isContract(address _addr) private view returns (bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length>0);
    }

    event Transfer(address indexed from, address indexed to, uint value);
    event Approval(address indexed owner, address indexed spender, uint value);
    event Mint(address indexed to, uint amount);
    event Burn(address indexed burner, uint value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
}
