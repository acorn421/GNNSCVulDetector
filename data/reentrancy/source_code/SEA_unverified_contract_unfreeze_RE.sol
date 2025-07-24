/*
 * ===== SmartInject Injection Details =====
 * Function      : unfreeze
 * Vulnerability : Reentrancy
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
 * Introduced a multi-transaction reentrancy vulnerability by adding an external call to the recipient after state updates. The vulnerability allows a malicious recipient contract to re-enter the unfreeze function during the callback, enabling exploitation across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the recipient address
 * 2. Introduced an external call to `onTokensUnfrozen` callback after state variables are updated
 * 3. The external call violates the Checks-Effects-Interactions pattern by occurring after state changes
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls unfreeze() for a malicious contract address
 * 2. **During TX1**: After state update, callback triggers malicious contract's onTokensUnfrozen()
 * 3. **Reentrant Call**: Malicious contract calls back into unfreeze() or other functions while original call is still executing
 * 4. **Transaction 2**: Subsequent calls can exploit the intermediate state created by the first transaction
 * 5. **State Accumulation**: Multiple unfreeze calls can be chained together, allowing the attacker to accumulate more tokens than intended
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the recipient to be a contract (not an EOA)
 * - The malicious contract must be deployed in a previous transaction
 * - The attack involves setting up state across multiple calls where each callback can trigger additional unfreezes
 * - The attacker needs to orchestrate a sequence of calls where each transaction builds upon the state changes from previous transactions
 * - The exploit cannot be contained within a single atomic transaction because it depends on the callback mechanism and accumulated state changes
 * 
 * **Realistic Nature:**
 * This vulnerability pattern is realistic because:
 * - Many token contracts implement callback mechanisms for better UX
 * - The callback happens after state changes, which is a common mistake
 * - The owner-only restriction makes the vulnerability seem less obvious
 * - The functionality is preserved while introducing the security flaw
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update state variables
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        freezes[_to] = freezes[_to].sub(_value);
		balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify recipient - VULNERABILITY: Call after state changes
        if (isContract(_to)) {
            // This external call allows reentrancy into the contract
            // The recipient can call back into unfreeze or other functions
            (bool callSuccess,) = _to.call(
                abi.encodeWithSignature("onTokensUnfrozen(uint256)", _value)
            );
            // Continue regardless of callback success to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Unfreeze(_to, _value);
        return true;
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
