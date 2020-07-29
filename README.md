# DDoS DeepLearning Approach

使用深度学习模型完成的DDoS流识别。

## 模型

在DDoS中，以流为单位获取相关的统计量进行处理是不太现实的，在实际的运行环境之下，难以直接获得整一个流的相关统计信息。

在选取模型的时候，参照了[LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection](https://arxiv.org/abs/2002.04902)中给出的基于卷积神经网络的模型进行训练，以一个流在给定时间段内的数据包来进行特征提取，用于模型的输入。

模型的参数如下，实际训练运行的时候可以按照需求调整内部参数，整体保持一个先卷积网络再全连接网络的结构即可。

```
Model: "DCNNModel"
_________________________________________________________________
Layer (type)                 Output Shape              Param #   
=================================================================
input_1 (InputLayer)         [(None, 100, 155)]        0         
_________________________________________________________________
reshape (Reshape)            (None, 100, 155, 1)       0         
_________________________________________________________________
conv2d (Conv2D)              (None, 50, 78, 8)         520       
_________________________________________________________________
conv2d_1 (Conv2D)            (None, 25, 39, 16)        8208      
_________________________________________________________________
max_pooling2d (MaxPooling2D) (None, 7, 20, 16)         0         
_________________________________________________________________
flatten (Flatten)            (None, 2240)              0         
_________________________________________________________________
dense (Dense)                (None, 32)                71712     
_________________________________________________________________
batch_normalization (BatchNo (None, 32)                128       
_________________________________________________________________
dense_1 (Dense)              (None, 16)                528       
_________________________________________________________________
batch_normalization_1 (Batch (None, 16)                64        
_________________________________________________________________
dense_2 (Dense)              (None, 2)                 34        
_________________________________________________________________
softmax (Softmax)            (None, 2)                 0         
=================================================================
Total params: 81,194
Trainable params: 81,098
Non-trainable params: 96
_________________________________________________________________
```

## CIC DDoS 2019上的数据集导入

数据集目前选择了[CIC DDoS 2019数据集](https://www.unb.ca/cic/datasets/ddos-2019.html)。

该数据集在各个不同的时间阶段具有不同的攻击流量类型，因此较为适合分别对不同类型的流量进行测试。

由于CIC DDoS 2019数据集中大部分都属于攻击流量，正常的访问流量很少，因此在导入这一数据集中的攻击流量的同时，选择了从外部加载正常流量，可以使用自己抓包获取到的`*.pcap`格式文件，并在传递给`data_loaders.No_Label_Pcap_Set.preprocess_loader.load_feature`函数的`pcap_file_list`参数的Python列表中添加这一抓包文件的文件路径，即可导入新的抓包数据。

对于CIC DDoS 2019数据集中流量的导入，则使用了一个通用的`data_loaders.Generic_Pcap_Dataset`中的代码，和一部分来自`data_loaders.CIC_DDoS_2019`中的数据预处理的代码进行导入。在有新增的带标签数据集时，可以替换数据集专有的代码来兼容新数据集。

### 流量特征提取

训练所使用的流量特征不包含任何的IP、端口信息，因此完全取基于报文的具体内容来对流量进行识别和判断。特征提取的内容参考了开始提到的论文中所使用的特征，另外还可以进行扩充。所有的特征都采用了对应的方法进行规范化，以转化为[0,1]之间的浮点数分布。

| 特征类型     | 规范化                                                       | 说明                                                         |
| ------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Time         | 在放大特定倍数（1000000倍）之后取整，转化为32位二进制数并视为32个浮点数字 | 当前数据包和所属的流中第一个数据包之间的时间间隔，第一个即为0 |
| PKT Len      | 取16位二进制后规范化为浮点数，超出位数截断为全1的16位特征向量 |                                                              |
| IP Flags     | 取16位二进制后规范化为浮点数                                 | 这一特征，以及之后的特征，由于本身具有范围，不用考虑截断     |
| Protocols    | 取8位二进制后规范化为浮点数                                  | 和IP报文的协议位数字对应                                     |
| TCP Len      | 取16位二进制后规范化为浮点数                                 |                                                              |
| TCP ACK      | 取32位二进制后规范化为浮点数                                 |                                                              |
| TCP Flags    | 取8位二进制后规范化为浮点数                                  |                                                              |
| TCP win size | 取16位二进制后规范化为浮点数                                 |                                                              |
| UDP Len      | 取16位二进制后规范化为浮点数                                 |                                                              |

以上特征合计160位，这一参数需要和训练时所采用的模型的形状对应。

## 训练和预测

训练过程使用一个简单的Trainer即可完成，之前数据导入的过程比较复杂所以占据主要内容。在`experiments.dcnn_on_cic_ddos_2019`中定义了完整的训练和预测过程，使用IS_TRAINING这一布尔变量控制训练和预测。

使用预处理从CIC DDoS 2019数据集中加载10000份攻击流量，并通过本地抓包制作正常流量，并导入，同样生成10000份正常流量，用于模型的训练，训练结果如下：

```
WARNING:__main__:Programme started in train mode!
INFO:__main__:Loading normal flow...
100%|████████████████████████████████████████| 4/4 [00:53<00:00, 13.36s/it, Loaded flow number=1e+4]
INFO:__main__:Loading attack flow...
INFO:templates.utils:Cache is loaded from cache/generic_loader/7-28T05-02/label_from_csv_cache
100%|██████████████████████████████████| 30/30 [00:09<00:00,  3.19it/s, BENIGN=0, MSSQL=0, UDP=1e+4]
INFO:root:Generating dataset...
100%|███████████████████████████████████████████████████| 183227/183227 [00:00<00:00, 919449.29it/s]
INFO:templates.utils:Cache is saved to cache/generic_loader/7-28T05-02/combine_set_cache
INFO:templates.utils:Cache is loaded from cache/generic_loader/7-28T05-02/combine_set_cache
Epoch 1/2
INFO:templates.utils:Cache is loaded from cache/generic_loader/7-28T05-02/combine_set_cache
2000/2000 [==============================] - 29s 14ms/step - loss: 0.1175 - categorical_accuracy: 0.9808 - categorical_crossentropy: 0.1175
Epoch 2/2
INFO:templates.utils:Cache is loaded from cache/generic_loader/7-28T05-02/combine_set_cache
2000/2000 [==============================] - 28s 14ms/step - loss: 0.0344 - categorical_accuracy: 0.9960 - categorical_crossentropy: 0.0344
INFO:__main__:Saving weight...
```

预测模式下，将从网络设备（需要修改INTERFACE变量以指定为当前的网络设备）中进行抓包并预测攻击流量的比例。以下测试中第一轮正在经历攻击流量的重放，因此预测出来的比例很高，后一轮则只有常规的网页访问操作，因此预测出攻击的比例很低。

```
WARNING:__main__:Programme started in predict mode!
INFO:__main__:Start capture and predict...
INFO:__main__:Predict turn 1
INFO:__main__:Capturing...
INFO:__main__:Capture done, generating predict set...
100%|████████████████████████████████████████| 1/1 [00:02<00:00,  2.50s/it, Loaded flow number=3943]
100%|██████████████████████████████████████████████████████| 9730/9730 [00:00<00:00, 1324373.78it/s]
INFO:templates.utils:Cache is saved to cache/generic_loader/7-28T05-02/combine_set_cache(predict)
INFO:templates.utils:Cache is loaded from cache/generic_loader/7-28T05-02/combine_set_cache(predict)
WARNING:__main__:Attack: about 96%
INFO:__main__:Predict turn 2
INFO:__main__:Capturing...
INFO:__main__:Capture done, generating predict set...
100%|█████████████████████████████████████████| 1/1 [00:03<00:00,  3.12s/it, Loaded flow number=274]
100%|███████████████████████████████████████████████████████| 1970/1970 [00:00<00:00, 533633.36it/s]
INFO:templates.utils:Cache is saved to cache/generic_loader/7-28T05-02/combine_set_cache(predict)
INFO:templates.utils:Cache is loaded from cache/generic_loader/7-28T05-02/combine_set_cache(predict)
WARNING:__main__:Attack: about 1%
```

