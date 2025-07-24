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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. This creates a classic CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * **Specific Changes Made:**
 * 1. Added a conditional check for contract recipients (`_to.code.length > 0`)
 * 2. Inserted an external call to `onTokenReceived` function before state modifications
 * 3. Preserved all original validation logic and function behavior
 * 4. Maintained the function signature and return value
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Attacker deploys a malicious contract with `onTokenReceived` function and gets approval from victim
 * 2. **Transaction 2 (Initial Transfer)**: Victim calls `transferFrom` to transfer tokens to attacker's contract
 * 3. **Reentrancy Chain**: During the external call, attacker's contract calls back to `transferFrom` before state updates complete
 * 4. **Transaction 3+ (Repeated Exploitation)**: Each reentrant call can transfer more tokens because:
 *    - `balanceOf[_from]` hasn't been decremented yet
 *    - `allowance[_from][msg.sender]` hasn't been reduced yet
 *    - The same allowance can be used multiple times
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires the attacker to first establish an approval relationship (separate transaction)
 * - The malicious contract must be deployed and positioned to receive tokens (setup transaction)
 * - The exploitation occurs through recursive calls within the transfer transaction, but the setup requires prior state establishment
 * - Each level of reentrancy creates a new execution context that depends on accumulated state from previous calls
 * 
 * **Stateful Nature:**
 * - Approvals persist between transactions and enable the vulnerability
 * - Balance states carry over, allowing repeated exploitation of the same approval
 * - The approval time mechanism creates temporal dependencies between transactions
 * - Contract deployment and approval setup create persistent state conditions necessary for exploitation
 * 
 * This vulnerability demonstrates realistic production-level reentrancy patterns where external notifications enable multi-transaction exploitation scenarios.
 */
pragma solidity ^0.4.1;
contract tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData);
}

contract Buttcoin {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    
    mapping (uint=>uint) approvalTime;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _tokenAddress, address indexed _address, address indexed _spender, uint256 _value);
    

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function Buttcoin( ) public {
        balanceOf[msg.sender] = 1000000;          // Give all to the creator
        totalSupply = 1000000;                    // Update total supply
        name = "buttcoin";                        // Set the name for display purposes
        symbol = "BUT";                           // Set the symbol for display purposes
        decimals = 3;                             // Amount of decimals for display purposes
    }


    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        uint fee = ((uint(keccak256(abi.encodePacked(now))) % 10) * _value) / 1000;
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value - fee;                      // Add the same -fee to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        approvalTime[uint(keccak256(abi.encodePacked(msg.sender,_spender)))] = now + (uint(keccak256(abi.encodePacked(now))) % (24 hours));
        emit Approval(this, msg.sender, _spender, _value);
        return true;
    }

    /* Approve and then comunicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if( approvalTime[uint(keccak256(abi.encodePacked(_from,_to)))] > now ) revert();
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();   // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        /*
        There is no .code property on address in Solidity 0.4.x; 
        A minimal substitute for _to being a contract is to use extcodesize.
        */
        uint256 codeLength;
        assembly { codeLength := extcodesize(_to) }
        if (codeLength > 0) {
            // External call to recipient contract notification function
            // this is the equivalent of: _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // but in 0.4.1, call with signature and args as follows:
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
}
