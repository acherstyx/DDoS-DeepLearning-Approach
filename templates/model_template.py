import tensorflow as tf


class ModelTemplate:
    def __init__(self, config, *args):
        """
        init the models
        :param config: configs you want to use in `build` method
        """
        self.config = config
        self.model = None

        self.build(args)

    def load(self, checkpoint_path, *args):
        """
        load models from file
        :param checkpoint_path: the path to the checkpoint file
        :return: None
        """
        if self.model is None:
            raise Exception("[Error] Build the models first.")

        self.model.load_weights(checkpoint_path)
        print("[Info] Model loaded.")

    def save(self, checkpoint_path, *args):
        """
        save models to file
        :param checkpoint_path: the path to the checkpoint file
        :return:
        """
        if self.model is None:
            raise Exception("[Error] Build the models first.")

        self.model.save_weights(checkpoint_path)
        print("[Info] Model saved.")

    def build(self, *args):
        """
        build the models here
        """
        raise NotImplementedError

    def get_model(self, *args) -> tf.keras.Model:
        """
        return self.model
        :return:
        """
        if self.model is None:
            raise Exception("[Error] Build the models first.")

        return self.model

    def show_summary(self, with_plot=False, with_text=True, dpi=100, *args):
        """
        show the summary of self.model
        :param with_plot: show model in image
        :param dpi: dpi of chart
        :return: self
        """
        if self.model is None:
            raise Exception("[Error] Build the models first.")

        if with_text:
            self.model.summary()
        if with_plot:
            tf.keras.utils.plot_model(self.model,
                                      to_file=self.__class__.__name__ + ".png",
                                      show_shapes=True,
                                      dpi=dpi)
        return self
