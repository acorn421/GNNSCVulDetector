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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after updating balances but before updating allowances. This creates a reentrancy window where the recipient can manipulate state across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call()` with `onTokenReceived` callback after balance updates
 * 2. Positioned the call after `balances` updates but before `allowed` updates
 * 3. Used low-level call to avoid reverting on failure, maintaining function behavior
 * 4. Added code length check to only call contracts, not EOAs
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract as recipient
 * - Attacker or accomplice approves tokens to the malicious contract
 * - Sets up the attack state in the malicious contract
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Call `transferFrom(victim, maliciousContract, amount)`
 * - During execution:
 *   - `balances[victim]` decreases, `balances[maliciousContract]` increases
 *   - External call to `maliciousContract.onTokenReceived()` occurs
 *   - Malicious contract can now call other functions while `allowed[victim][msg.sender]` is NOT yet updated
 *   - Malicious contract can call `transferFrom` again with same allowance since it hasn't been decremented yet
 * 
 * **Transaction 3+ (Exploitation):**
 * - Malicious contract can continue exploiting the inconsistent state
 * - Can perform additional transfers using the same allowance multiple times
 * - Can manipulate other contract functions that depend on balance/allowance state
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: The attack relies on building up state across multiple calls
 * 2. **Allowance Reuse**: The same allowance can be used multiple times before being decremented
 * 3. **Cross-Function Interaction**: The malicious contract can call other functions during the reentrancy window
 * 4. **Persistent State Changes**: Each transaction modifies persistent storage that affects subsequent transactions
 * 
 * This creates a realistic vulnerability where the inconsistent state between balance updates and allowance updates can be exploited across multiple transactions through the external call mechanism.
 */
pragma solidity ^0.4.16;

contract owned {
    address owner;
    constructor () public { owner = msg.sender; }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
}

contract TokenArtFinity is owned {
    
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    string public name = "ArtFinity";    //token name
    uint8 public decimals = 5;              
    string public symbol = "AT";           
    uint256 public totalSupply = 100000000000000; 
    GoodsTransferInfo[] public goodsTransferArray;

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    
    struct GoodsTransferInfo {
        address withDrawAddress;
        uint32 goodsId;
        uint32 goodsNum;
    }

    constructor () public {
        balances[msg.sender] = totalSupply; 
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferTokenWithGoods(address goodsWithdrawer, uint256 _value, uint32 goodsId, uint32 goodsNum) public onlyOwner returns (bool success) {
        
        require(balances[msg.sender] >= _value && balances[goodsWithdrawer] + _value > balances[goodsWithdrawer]);
        require(goodsWithdrawer != 0x0);
        balances[msg.sender] -= _value;
        balances[goodsWithdrawer] += _value;
        goodsTransferArray.push(GoodsTransferInfo(goodsWithdrawer, goodsId, goodsNum));
        emit Transfer(msg.sender, goodsWithdrawer, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value; 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add external call to notify recipient - creates reentrancy vector
        if (isContract(_to)) {
            // Uses a low-level call, preserves the vulnerability
            _to.call(abi.encodeWithSignature("onTokenReceived(address,uint256)", _from, _value));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success)   
    { 
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
    
    function goodsTransferArrayLength() public constant returns(uint256 length) {
        return goodsTransferArray.length;
    }
    
    // Helper in Solidity 0.4.x to check if address is a contract (since address.code does not exist)
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
