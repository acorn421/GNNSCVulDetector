/*
 * ===== SmartInject Injection Details =====
 * Function      : renounceOwnership
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a two-phase renunciation process:
 * 
 * **Changes Made:**
 * 1. **Added State Variables**: 
 *    - `renunciationRequests` mapping to track pending renunciation requests
 *    - `RENUNCIATION_DELAY` constant for block-based timing
 * 
 * 2. **Implemented Two-Phase Process**:
 *    - First transaction: Records request timestamp using `block.number`
 *    - Second transaction: Validates delay and uses `block.timestamp` for final decision
 * 
 * 3. **Timestamp Vulnerability**: Uses `block.timestamp % 2 == 0` for final validation, making the success dependent on when the transaction is mined
 * 
 * **Multi-Transaction Exploitation:**
 * This vulnerability requires exactly 2 transactions to exploit and involves timestamp manipulation:
 * 
 * **Transaction 1** (Initiate Request):
 * - Owner calls `renounceOwnership()` 
 * - Function records `block.number` in `renunciationRequests`
 * - Emits event but doesn't transfer ownership yet
 * 
 * **Transaction 2** (Complete Renunciation):
 * - After waiting for `RENUNCIATION_DELAY` blocks
 * - Owner calls `renounceOwnership()` again
 * - Function checks if enough blocks have passed
 * - **VULNERABILITY**: Uses `block.timestamp % 2 == 0` to determine success
 * - If timestamp is even: ownership renounced successfully
 * - If timestamp is odd: request reset, forcing retry
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Dependency**: The vulnerability relies on the persistent state from the first transaction (`renunciationRequests` mapping)
 * 2. **Time-Based Validation**: The delay mechanism requires multiple blocks to pass between transactions
 * 3. **Timestamp Manipulation Window**: Miners can manipulate `block.timestamp` within a 900-second window, allowing them to control whether the second transaction succeeds
 * 4. **Stateful Reset**: If the timestamp check fails, the state is reset, requiring the entire process to restart
 * 
 * **Exploitation Scenario:**
 * A malicious miner could:
 * 1. See the first renunciation request in the mempool
 * 2. Wait for the delay period to pass
 * 3. When the owner submits the second transaction, manipulate `block.timestamp` to ensure it's odd
 * 4. Force the renunciation to fail and reset, potentially indefinitely
 * 5. Or manipulate it to be even when it benefits them (e.g., if they want to acquire the contract)
 * 
 * This creates a realistic timestamp dependence vulnerability where the outcome depends on miner-controllable block properties across multiple transactions.
 */
pragma solidity ^0.4.22;
contract Ownable {
  address public owner;

  event OwnershipRenounced(address indexed previousOwner);
  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );

  /**
   * @dev 可拥有的构造函数将合同的原始“所有者”设置为发送者
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev 如果由所有者以外的任何帐户调用，则抛出
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev 允许业主放弃合同的控制权.
   */
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
  mapping(address => uint256) private renunciationRequests;
  uint256 private constant RENUNCIATION_DELAY = 10; // blocks
  
  function renounceOwnership() public onlyOwner {
    if (renunciationRequests[msg.sender] == 0) {
      // First call: initiate renunciation request
      renunciationRequests[msg.sender] = block.number;
      emit OwnershipRenounced(owner);
      return;
    }
    
    // Second call: complete renunciation after delay
    uint256 requestBlock = renunciationRequests[msg.sender];
    uint256 timePassed = block.number - requestBlock;
    
    if (timePassed >= RENUNCIATION_DELAY) {
      // Use block.timestamp for final validation - vulnerable to manipulation
      if (block.timestamp % 2 == 0) {
        owner = address(0);
        delete renunciationRequests[msg.sender];
      } else {
        // Reset request if timestamp is odd - forces retry
        renunciationRequests[msg.sender] = 0;
      }
    }
  }
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

  /**
   * @dev 将合同的控制权移交给新所有者.
   */
  function _transferOwnership(address _newOwner) internal {
    require(_newOwner != address(0));
    emit OwnershipTransferred(owner, _newOwner);
    owner = _newOwner;
  }
}

contract TokenMall is Ownable {
  /**
   * @dev 抵押物上链信息.
   */
  struct MortgageInfo {
      bytes32 projectId;//项目ID 
      string currency;//抵押币种 
      string mortgageAmount;//抵押数量 
      string releaseAmount;//释放数量 
  }
  mapping(bytes32 =>MortgageInfo) mInfo;
  bytes32[] mortgageInfos;
   
  /**
   * @dev 添加数据.
   */
    event MessageMintInfo(address sender,bool isScuccess,string message);
    function mintMortgageInfo(string _projectId,string currency,string mortgageAmount,string releaseAmount) onlyOwner public {
        bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId != proId){
              mInfo[proId].projectId = proId;
              mInfo[proId].currency = currency;
              mInfo[proId].mortgageAmount = mortgageAmount;
              mInfo[proId].releaseAmount = releaseAmount;
              mortgageInfos.push(proId);
              MessageMintInfo(msg.sender, true,"添加成功");
            return;
        }else{
             MessageMintInfo(msg.sender, false,"项目ID已经存在");
            return;
        }
    }
  /**
   * @dev 更新数据.
   */
    event MessageUpdateInfo(address sender,bool isScuccess,string message);
    function updateMortgageInfo(string _projectId,string releaseAmount) onlyOwner public {
         bytes32 proId = stringToBytes32(_projectId);
        if(mInfo[proId].projectId == proId){
              mInfo[proId].releaseAmount = releaseAmount;
              mortgageInfos.push(proId);
              MessageUpdateInfo(msg.sender, true,"修改成功");
            return;
        }else{
             MessageUpdateInfo(msg.sender, false,"项目ID不存在");
            return;
        }
    }
     
     
  /**
   * @dev 查询数据.
   */
    function getMortgageInfo(string _projectId) 
    public view returns(string projectId,string currency,string mortgageAmount,string releaseAmount){
         
         bytes32 proId = stringToBytes32(_projectId);
         
         MortgageInfo memory mi = mInfo[proId];
        
        return (_projectId,mi.currency,mi.mortgageAmount,mi.releaseAmount);
    }
    
     /// string类型转化为bytes32型转
    function stringToBytes32(string memory source) internal constant returns(bytes32 result){
        assembly{
            result := mload(add(source,32))
        }
    }
    /// bytes32类型转化为string型转
    function bytes32ToString(bytes32 x) internal constant returns(string){
        bytes memory bytesString = new bytes(32);
        uint charCount = 0 ;
        for(uint j = 0 ; j<32;j++){
            byte char = byte(bytes32(uint(x) *2 **(8*j)));
            if(char !=0){
                bytesString[charCount] = char;
                charCount++;
            }
        }
        bytes memory bytesStringTrimmed = new bytes(charCount);
        for(j=0;j<charCount;j++){
            bytesStringTrimmed[j]=bytesString[j];
        }
        return string(bytesStringTrimmed);
    }

}