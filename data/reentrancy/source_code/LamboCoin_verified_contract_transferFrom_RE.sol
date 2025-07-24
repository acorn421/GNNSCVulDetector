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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient contract after balance updates but before allowance decrementation. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` with `onTokenReceived` callback
 * 2. Positioned the external call after balance updates but before allowance reduction
 * 3. Added condition to only call if recipient is a contract (`_to.code.length > 0`)
 * 4. Disguised as a legitimate "transfer notification" feature for compliance/logging
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Victim approves allowance X for malicious spender
 * 2. **Transaction 2**: Spender calls `transferFrom` to malicious contract recipient
 * 3. **During external call**: Malicious recipient contract reenters `transferFrom` with same allowance
 * 4. **Result**: Multiple transfers using single allowance before it's decremented
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance must be pre-approved in a separate transaction (standard ERC20 pattern)
 * - The vulnerability only triggers when transferring to a contract that implements the callback
 * - The reentrant call uses the same allowance that hasn't been decremented yet
 * - State persistence between transactions (allowance approval) enables the exploit
 * 
 * **Stateful Nature:**
 * - Relies on persistent allowance state from previous approval transaction
 * - Each reentrant call can transfer tokens before allowance is updated
 * - Creates a race condition where multiple transfers can occur with single allowance
 * - The vulnerability accumulates across multiple calls until allowance is finally decremented
 * 
 * This creates a realistic vulnerability pattern where standard ERC20 usage (approve then transferFrom) combined with a seemingly innocent transfer notification feature creates an exploitable reentrancy condition that requires multiple transactions to fully exploit.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract LamboCoin {
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

	bool public purchasingAllowed = false;
    uint256 public totalContribution = 0;
    uint256 public totalSupply = 0;
	uint256 public maxSupply = 0;

    function name() constant returns (string) { return "LamboCoin"; }
    function symbol() constant returns (string) { return "LBC"; }
    function decimals() constant returns (uint8) { return 18; }
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }

    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        if (sufficientFunds && !overflowed) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;

            emit Transfer(msg.sender, _to, _value);
            return true;
        } else {
			return false;
		}
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { revert(); }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;

            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify recipient of transfer (potential compliance/logging requirement)
            if (isContract(_to)) {
                bool _callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
                // Continue regardless of callback success for backward compatibility
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;

            emit Transfer(_from, _to, _value);
            return true;
        } else {
			return false;
		}
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }

        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    function enablePurchasing() {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { revert(); }

        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { revert(); }

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, maxSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { revert(); }
        if (msg.value == 0) { return; }

		//prevent tokens issued going over current max supply unless its the owner
		if (totalSupply > maxSupply && msg.sender != owner) { revert(); }

        owner.transfer(msg.value);

        totalContribution += msg.value;
        uint256 tokensIssued = (msg.value * 100);
		totalSupply += tokensIssued;

		//Allow owner to increase max supply as desired
		if( msg.sender == owner ) {
			maxSupply += (msg.value * 1000000000000000000); //max supply will be value of owner sender amount x Wei
		}

		balances[msg.sender] += tokensIssued;
        emit Transfer(address(this), msg.sender, tokensIssued);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    // Internal helper to check if address is a contract
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }
}
