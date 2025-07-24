/*
 * ===== SmartInject Injection Details =====
 * Function      : issue
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy attack vector through the following mechanisms:
 * 
 * **1. Specific Code Changes Made:**
 * - Added `pendingIssuance[owner]` state variable to track cumulative pending issuances across transactions
 * - Introduced external call to `issuanceNotifier` contract before state finalization
 * - Moved critical state updates (balanceOf and totalSupply) to occur AFTER the external call (CEI violation)
 * - Added try-catch mechanism that manipulates pending state on callback failure
 * - Pending state is cleared only after successful issuance completion
 * 
 * **2. Multi-Transaction Exploitation Path:**
 * - **Transaction 1**: Legitimate issue() call creates pending state and triggers external callback
 * - **During Callback**: Malicious notifier contract can reenter issue() while pendingIssuance state is accumulated
 * - **Transaction 2**: Second issue() call sees accumulated pendingIssuance from previous transaction
 * - **Exploitation**: The accumulated pending state from multiple transactions can be manipulated to:
 *   - Double-count issuances by reentering during the callback
 *   - Manipulate the pending state calculations across transaction boundaries
 *   - Exploit the time window between pending state creation and finalization
 * 
 * **3. Why Multiple Transactions Are Required:**
 * - **State Accumulation**: The vulnerability depends on pendingIssuance state persisting between transactions
 * - **Callback Timing**: The external call creates a window where state is inconsistent across transaction boundaries
 * - **Gas Limitations**: Complex reentrancy attacks may require multiple transactions due to gas limits
 * - **Business Logic**: The pending state mechanism naturally requires multiple calls to build up exploitable conditions
 * - **Atomic Transaction Limitations**: Single transaction cannot exploit the accumulated state from previous transactions
 * 
 * **4. Realistic Attack Vector:**
 * An attacker could deploy a malicious issuanceNotifier contract that:
 * - Reenters issue() during the callback to accumulate pending state
 * - Manipulates the pending calculations by timing attacks across multiple transactions
 * - Exploits the inconsistent state between pending tracking and actual balance updates
 * 
 * This creates a genuine multi-transaction vulnerability that requires state accumulation across multiple function calls to be effectively exploited.
 */
pragma solidity ^0.4.18;

library SafeOpt {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0); 
        uint256 c = a / b;
        assert(a == b * c);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a - b;
        assert(b <= a);
        assert(a == c + b);
        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        assert(a == c - b);
        return c;
    }
}
contract TTBTokenIssue {
    uint256 public lastYearTotalSupply = 15 * 10 ** 26; 
    uint8   public affectedCount = 0;
    bool    public initialYear = true; 
	address public tokenContractAddress;
    uint16  public preRate = 1000; 
    uint256 public lastBlockNumber;

    function TTBTokenIssue (address _tokenContractAddress) public{
        tokenContractAddress = _tokenContractAddress;
        lastBlockNumber = block.number;
    }

    function returnRate() internal returns (uint256){
        if(affectedCount == 10){
            if(preRate > 100){
                preRate -= 100;
            }
            affectedCount = 0;
        }
        return SafeOpt.div(preRate, 10);
    }

    function issue() public  {
        if(initialYear){
            require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
            initialYear = false;
        }
        require(SafeOpt.sub(block.number, lastBlockNumber) > 2102400);
        TTBToken tokenContract = TTBToken(tokenContractAddress);
        if(affectedCount == 10){
            lastYearTotalSupply = tokenContract.totalSupply();
        }
        uint256 amount = SafeOpt.div(SafeOpt.mul(lastYearTotalSupply, returnRate()), 10000);
        require(amount > 0);
        tokenContract.issue(amount);
        lastBlockNumber = block.number;
        affectedCount += 1;
    }
}

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

// Define a simple interface for issuance notification
interface IIssuanceNotifier {
    function onTokenIssuance(address owner, uint256 amount, uint256 pending) external;
}

contract TTBToken {
    string public name = 'Tip-Top Block';
    string public symbol = 'TTB';
    uint8 public decimals = 18;
    uint256 public totalSupply = 100 * 10 ** 26;

    address public issueContractAddress;
    address public owner;
    
    // MISSING STATE VARIABLES (added below as per how they are used in the vulnerable function)
    mapping(address => uint256) public pendingIssuance;
    address public issuanceNotifier;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
    event Burn(address indexed from, uint256 value);
    event Issue(uint256 amount);

    function TTBToken() public {
        owner = msg.sender;
        balanceOf[owner] = totalSupply;
        issueContractAddress = new TTBTokenIssue(address(this));
    }

    function issue(uint256 amount) public {
        require(msg.sender == issueContractAddress);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Track pending issuance for multi-transaction exploitation
        pendingIssuance[owner] = SafeOpt.add(pendingIssuance[owner], amount);
        
        // External call to notify stakeholders about issuance before state finalization
        if (issuanceNotifier != address(0)) {
            // Since try/catch is not available in Solidity 0.4.18, use external call and manual revert logic.
            // The following is the adapted equivalent:
            bool ok = address(issuanceNotifier).call(bytes4(keccak256("onTokenIssuance(address,uint256,uint256)")), owner, amount, pendingIssuance[owner]);
            if (!ok) {
                // Revert pending issuance on callback failure
                pendingIssuance[owner] = SafeOpt.sub(pendingIssuance[owner], amount);
                revert();
            }
        }
        
        // State changes occur after external call - CEI violation
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[owner] = SafeOpt.add(balanceOf[owner], amount);
        totalSupply = SafeOpt.add(totalSupply, amount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Clear pending only after successful issuance
        pendingIssuance[owner] = SafeOpt.sub(pendingIssuance[owner], amount);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Issue(amount);
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balanceOf[_owner];
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

    function transfer(address _to, uint256 _value) public returns (bool success){
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value <= balanceOf[msg.sender]);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    function allowance(address _owner, address _spender) view public returns (uint256 remaining) {
        return allowance[_owner][_spender];
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