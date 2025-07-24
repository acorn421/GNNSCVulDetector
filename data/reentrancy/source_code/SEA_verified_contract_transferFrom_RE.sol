/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract's onTokenReceived function BEFORE state updates. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first deploy a malicious contract and set up allowances in separate transactions
 * 2. **State Dependency**: The vulnerability exploits the fact that balances and allowances haven't been updated when the external call is made
 * 3. **Sequential Exploitation**: The malicious contract can call transferFrom recursively during the callback, draining funds across multiple nested calls
 * 
 * The vulnerability requires:
 * - Transaction 1: Deploy malicious contract
 * - Transaction 2: Set allowances for the malicious contract
 * - Transaction 3: Trigger transferFrom which calls the malicious contract's onTokenReceived
 * - During Transaction 3: The malicious contract can recursively call transferFrom multiple times before state is updated
 * 
 * This is realistic because token notification callbacks are common in DeFi, but the placement before state updates creates the vulnerability. The attacker's contract can maintain state across the recursive calls to track and limit exploitation.
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
			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
			// Check if recipient is a contract and has a notification interface
			uint codeLength;
			assembly { codeLength := extcodesize(_to) }
			if (codeLength > 0) {
				// Try to call the recipient's notification method before state updates
				// Rename the local variable to avoid conflict with the function return variable
				bool callSuccess = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, sendAmount));
				// Continue regardless of callSuccess to maintain compatibility
			}
			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
