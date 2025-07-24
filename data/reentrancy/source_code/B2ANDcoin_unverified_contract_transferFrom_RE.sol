/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **VULNERABILITY DESCRIPTION:**
 * 
 * **Specific Changes Made:**
 * 1. Added a callback mechanism that invokes `receiveApproval` on the recipient address if it's a contract
 * 2. The callback occurs AFTER the allowance is decremented but potentially during the transfer process
 * 3. The callback provides access to the inconsistent state where allowance is reduced but the full transfer effects may not be complete
 * 4. Used try-catch to prevent reverting, making the vulnerability more subtle and realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Victim approves a large allowance for the attacker's malicious contract
 * - `approve(attackerContract, 1000 tokens)`
 * 
 * **Transaction 2 (Initial transferFrom):**
 * - Attacker calls `transferFrom(victim, attackerContract, 100)`
 * - Contract decrements allowance: `allowance[victim][attacker] -= 100` (now 900)
 * - `_transfer` begins execution
 * - Callback triggers `receiveApproval` on attacker's contract
 * 
 * **Transaction 3-N (Reentrancy during callback):**
 * - Inside `receiveApproval`, attacker can call `transferFrom` again
 * - Each call decrements allowance before completing the full transfer
 * - Attacker can drain more tokens than originally approved by exploiting the inconsistent state between allowance decrement and transfer completion
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The vulnerability requires building up allowance through `approve()` in separate transactions
 * 2. **Callback Chain**: Each `transferFrom` call creates a new callback opportunity, requiring multiple transaction depths
 * 3. **Allowance Depletion**: The exploit involves gradually depleting allowance across multiple nested calls
 * 4. **Contract Deployment**: The malicious contract needs to be deployed and approved in prior transactions
 * 
 * **Realistic Exploitation Path:**
 * 1. Deploy malicious contract with `receiveApproval` that calls `transferFrom` recursively
 * 2. Get victim to approve large allowance
 * 3. Call `transferFrom` which triggers the callback chain
 * 4. Each callback can call `transferFrom` again before the previous call completes
 * 5. Drain allowance faster than intended due to state inconsistency
 * 
 * This creates a stateful, multi-transaction vulnerability that requires preparation across multiple transactions and exploits the CEI (Check-Effects-Interactions) pattern violation in a realistic token transfer scenario.
 */
pragma solidity ^0.4.16;
 /**
     * B2AND Token contract
     *
     * The final version 2018-02-18
*/
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }
contract Ownable {
    address public owner;
    function Ownable() public {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }
}
contract B2ANDcoin is Ownable {
    string public name;
    string public symbol;
    uint8 public decimals = 18;   
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    function B2ANDcoin(
    ) public {
        totalSupply = 100000000 * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;               
        name = "B2ANDcoin";                                
        symbol = "B2C";                  
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
    }
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);    
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add callback to recipient if it's a contract
        if (isContract(_to)) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
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
